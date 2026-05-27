from __future__ import annotations
import re
import math
import zlib
from typing import List
from ...enums import ThreatID, Severity, VerdictClass
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


def _decompress_flate_streams(data: bytes, max_bytes: int = 4 * 1024 * 1024) -> bytes:
    """Extract and decompress all FlateDecode streams found in raw PDF bytes.

    Returns the concatenated decompressed content so callers can scan it for
    active-content tokens and CMap markers that would otherwise be invisible
    in the compressed form.
    """
    # Locate stream boundaries.  The regex is intentionally non-greedy so we
    # collect each stream separately rather than one giant blob.
    _STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)

    out_parts: list[bytes] = []
    total = 0
    for m in _STREAM_RE.finditer(data):
        raw_stream = m.group(1)
        # Only decompress if /FlateDecode is mentioned near the stream header
        header_start = max(0, m.start() - 512)
        header_bytes = data[header_start:m.start()]
        if b"FlateDecode" not in header_bytes:
            continue
        try:
            # Use decompressobj with a hard per-stream byte cap so a bomb stream
            # (small compressed → gigabytes decompressed) cannot OOM or hang us.
            budget = max_bytes - total
            if budget <= 0:
                break
            chunk = zlib.decompressobj().decompress(raw_stream, budget)
            out_parts.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        except zlib.error:
            continue  # corrupt or non-zlib stream; skip
    return b" ".join(out_parts)


def _preprocess_pdf_bytes(data: bytes) -> bytes:
    """Decode hex-encoded strings and remove line continuations from PDF bytes.

    PDF allows /JavaScript to be written as <4a617661536372697074> or split
    across lines as /Java\\nScript.  Both forms evade exact-byte token matching.
    This function normalises those representations before token scanning.
    """
    # 1. Decode <hexstring> tokens.  Each pair of hex digits becomes one byte.
    def _hex_replace(m: re.Match) -> bytes:
        hex_content = m.group(1)
        try:
            return bytes.fromhex(hex_content.decode("ascii", errors="ignore"))
        except ValueError:
            return m.group(0)

    data = re.sub(rb"<([0-9a-fA-F\s]+)>", _hex_replace, data)
    # 2. Remove PDF line-continuation sequences (backslash immediately before newline).
    data = re.sub(rb"\\\r?\n", b"", data)
    return data


_MAX_XOBJECT_GRAPH_NODES = 200  # bail out on pathological graphs
# Bomb PDFs often contain thousands of objects; use a simple count as a fast
# pre-check.  data.count(b" obj") is O(n) with a small constant — much faster
# than running a regex finditer over binary stream content.
_MAX_OBJ_TOKENS_FOR_CYCLE_SCAN = 3000
_OBJ_HEADER_RE = re.compile(rb"(\d+)\s+0\s+obj\b")
_FORM_SUB_RE = re.compile(rb"/Subtype\s*/Form\b")
_XOBJ_REFS_RE = re.compile(rb"/XObject\s*<<([^>]*)>>")
_REF_RE_XOBJ = re.compile(rb"(\d+)\s+0\s+R")
_XOBJ_BODY_WINDOW = 4096  # bytes after each obj header to inspect

def _detect_xobject_cycles(data: bytes) -> bool:
    """Return True if the PDF byte stream contains circular Form XObject references.

    Builds a reference graph from /Resources /XObject dictionaries and runs a
    DFS to detect back-edges (cycles).  A cycle causes infinite recursion in
    PDF renderers and parsers — a DoS vector.

    Returns True immediately if the data contains too many `obj` tokens — a
    bomb PDF indicator that also protects against O(n²) regex performance on
    binary stream content.  Returns True if the XObject graph exceeds
    _MAX_XOBJECT_GRAPH_NODES nodes.
    """
    # O(n) fast pre-check: bomb PDFs have thousands of object tokens.
    # This also avoids running a regex over binary stream content where
    # `(\d+)\s+0\s+obj\b` can produce millions of false matches.
    if data.count(b" obj") > _MAX_OBJ_TOKENS_FOR_CYCLE_SCAN:
        return True

    graph: dict[int, list[int]] = {}

    for obj_match in _OBJ_HEADER_RE.finditer(data):
        obj_num = int(obj_match.group(1))
        # Scan only the next _XOBJ_BODY_WINDOW bytes — avoids (.*?)endobj
        # backtracking that hangs on bomb PDFs missing endobj terminators.
        obj_body = data[obj_match.end() : obj_match.end() + _XOBJ_BODY_WINDOW]
        if not _FORM_SUB_RE.search(obj_body):
            continue
        refs: list[int] = []
        xobj_m = _XOBJ_REFS_RE.search(obj_body)
        if xobj_m:
            for ref_m in _REF_RE_XOBJ.finditer(xobj_m.group(1)):
                refs.append(int(ref_m.group(1)))
        graph[obj_num] = refs
        if len(graph) > _MAX_XOBJECT_GRAPH_NODES:
            return True  # oversized graph is a DoS indicator

    if not graph:
        return False

    # Iterative DFS cycle detection — avoids Python recursion depth limit
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[int, int] = {n: WHITE for n in graph}

    def dfs(start: int) -> bool:
        stack = [(start, iter(graph.get(start, [])))]
        color[start] = GRAY
        while stack:
            node, children = stack[-1]
            try:
                nb = next(children)
                state = color.get(nb, WHITE)
                if state == GRAY:
                    return True
                if state == WHITE and nb in graph:
                    color[nb] = GRAY
                    stack.append((nb, iter(graph.get(nb, []))))
            except StopIteration:
                color[node] = BLACK
                stack.pop()
        return False

    return any(dfs(n) for n in list(graph) if color.get(n, WHITE) == WHITE)

# Tokens to watch for in raw stream. /URI and /AcroForm are intentionally
# excluded — a /URI is just a hyperlink (resumes and any normal PDF have
# mailto: / https:// references), and a form by itself is not malicious.
# /URI is handled separately below by _scan_suspicious_uris() which only
# flags javascript:/data:/file:/vbscript:/jar:/IP-literal targets.
# Mirror of pdf/active_content.py — kept in sync.
SUSPICIOUS_TOKENS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Filespec",
    b"/Encrypt",
    # B.2: XFA forms, form-action types, and sound actions — data-exfiltration
    # and remote-trigger vectors not covered by the base token set.
    b"/XFA",
    b"/SubmitForm",
    b"/ImportData",
    b"/ResetForm",
    b"/Named",
    b"/Sound",
    # D.7: Multimedia / 3D / smuggling vectors
    b"/RichMedia",     # Embedded Flash/SWF launcher (still parsed by some readers)
    b"/3D",            # PRC/U3D streams; can carry embedded JavaScript
    b"/Movie",         # Legacy multimedia annotation
    b"/GoToE",         # GoTo-Embedded action — used in document-smuggling chains
    b"/JBIG2Decode",   # CVE-2021-30860 carrier (FORCEDENTRY/Pegasus)
]

# URL schemes that should never appear in a benign PDF hyperlink. Mirrors
# pdf/active_content.py — kept in sync. Plain http(s)/mailto/tel pass silently.
_SUSPICIOUS_URI_SCHEMES_RE = re.compile(
    rb"^(?:javascript|data|vbscript|file|jar):", re.IGNORECASE
)
_IP_LITERAL_HOST_RE = re.compile(
    rb"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE
)
# Match a /URI ( ... ) entry. Cap inner capture so a malformed PDF can't
# blow up the regex on a giant span.
_URI_ENTRY_RE = re.compile(rb"/URI\s*\(([^)\\]{1,2000})\)")


def _scan_suspicious_uris(data: bytes) -> list[dict]:
    """Return a list of {target} for any /URI entries whose target uses a
    suspicious scheme. Plain http(s)/mailto/tel hyperlinks return nothing."""
    out: list[dict] = []
    for m in _URI_ENTRY_RE.finditer(data):
        target = m.group(1).strip()
        if _SUSPICIOUS_URI_SCHEMES_RE.match(target) or _IP_LITERAL_HOST_RE.match(target):
            try:
                decoded = target.decode("latin-1", errors="replace")[:200]
            except Exception:
                decoded = "<unprintable>"
            out.append({"target": decoded})
            if len(out) >= 20:
                break
    return out

# D.7: Tokens that warrant CRITICAL severity when found alongside an anomaly.
_CVE_PDF_TOKENS = {
    b"/JBIG2Decode": ("CVE-2021-30860", "T1203"),
    b"/RichMedia":   (None,            "T1203"),
}

# Simple Soft-Signal keywords for Prompt Injection (triage only)
STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def fast_scan_pdf(file_path: str, config: ScanConfig) -> List[Finding]:
    findings = []

    limit_bytes = config.limits.fast_pdf_token_scan_mb * 1024 * 1024

    with open(file_path, "rb") as f:
        data = f.read(limit_bytes)

    # 1. Token Scan (Active Content)
    # Valid PDF delimiters to ensure token is a real key
    delims_pattern = b"[\x00\t\n\f\r ()<>\\[\\]{}/%]"

    for token in SUSPICIOUS_TOKENS:
        if token in data:
            # Verify it's a valid key (must be followed by a delimiter)
            if not re.search(re.escape(token) + delims_pattern, data):
                continue

            sev = Severity.MEDIUM
            if token in [
                b"/OpenAction", b"/Launch", b"/Encrypt",
                b"/SubmitForm", b"/XFA",  # data exfiltration vectors
                b"/RichMedia", b"/GoToE",  # D.7
            ]:
                sev = Severity.HIGH

            cve_meta = _CVE_PDF_TOKENS.get(token, (None, None))
            findings.append(
                Finding(
                    threat_id=(
                        ThreatID.T2_ACTIVE_CONTENT
                        if token != b"/Encrypt"
                        else ThreatID.T3_OBFUSCATION
                    ),
                    severity=sev,
                    title="Suspicious PDF Token found: {}".format(
                        token.decode("ascii", errors="ignore")
                    ),
                    explain="Found suspicious token '{}' in raw file stream.".format(
                        token.decode("ascii", errors="ignore")
                    ),
                    evidence={"token": token.decode("ascii", errors="ignore")},
                    confidence=0.65,
                    module="fast_scan.pdf.tokens",
                    cve=cve_meta[0],
                    mitre_technique=cve_meta[1],
                )
            )

    # /URI is checked separately — only flag entries whose target uses a
    # suspicious scheme (javascript:/data:/file:/vbscript:/jar:) or an
    # IP-literal host. Plain http(s)/mailto/tel hyperlinks (LinkedIn, email,
    # phone) are not flagged.
    suspicious_uris = _scan_suspicious_uris(data)
    if suspicious_uris:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                title="PDF contains hyperlink with suspicious URL scheme",
                explain=(
                    "/URI entries reference javascript:, data:, file:, "
                    "vbscript:, jar:, or IP-literal targets. Plain http(s)/"
                    "mailto/tel hyperlinks are not flagged."
                ),
                evidence={
                    "suspicious_uris": suspicious_uris,
                    "malicious_text": suspicious_uris[0]["target"],
                },
                confidence=0.9,
                module="fast_scan.pdf.uris",
                # Same definitive bucket as the deep-scan path.
                verdict_class=VerdictClass.BLOCK,
            )
        )

    # D.7: JBIG2 dimension anomaly — CVE-2021-30860 used a JBIG2 stream with
    # an oversized /Width to overflow a 32-bit integer in CoreGraphics.
    # Legitimate document images rarely exceed 10 000 px wide.
    if b"/JBIG2Decode" in data:
        _DIM_RE = re.compile(rb"/Width\s+(\d{5,})|/Height\s+(\d{5,})")
        for _dim_m in _DIM_RE.finditer(data):
            try:
                val = int(_dim_m.group(1) or _dim_m.group(2))
            except (TypeError, ValueError):
                continue
            if val > 10_000:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.CRITICAL,
                        title="PDF JBIG2 Dimension Anomaly (Possible CVE-2021-30860)",
                        explain=(
                            f"JBIG2-decoded image with {val} px dimension — "
                            "well beyond legitimate document use. CVE-2021-30860 "
                            "(FORCEDENTRY) exploited oversized JBIG2 dimensions "
                            "for integer overflow."
                        ),
                        evidence={
                            "subtype": "jbig2_oversize",
                            "dimension": val,
                            "malicious_text": f"JBIG2 dimension {val}",
                        },
                        confidence=0.90,
                        module="fast_scan.pdf.jbig2",
                        cve="CVE-2021-30860",
                        mitre_technique="T1203",
                        # JBIG2 + dimension > 10K px is the CVE-2021-30860
                        # (FORCEDENTRY) exploit signature — definitive.
                        verdict_class=VerdictClass.BLOCK,
                    )
                )
                break

    # 2. Prompt Injection Keyword Scan
    # Scan raw PDF bytes for known injection keywords to trigger deep scan.
    # Severity=LOW / confidence=0.45 so this finding alone never crosses FLAG
    # threshold — it exists solely to push fast_score past deep_scan_trigger.
    # Deep scan runs the full T4 pipeline (regex + Aho-Corasick + BERT) on
    # parsed body text, which avoids the metadata/body confusion that made
    # this check unsafe at higher severity.
    data_lower = data.lower()
    seen_pdf_kw: set[bytes] = set()
    for kw in config.prompt_injection_keywords_bytes:
        if kw in data_lower and kw not in seen_pdf_kw:
            seen_pdf_kw.add(kw)
            findings.append(Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.LOW,
                title="Prompt Injection Keyword in PDF Stream",
                explain=f"Found injection keyword '{kw.decode('ascii', errors='replace')}' in raw PDF bytes — triggers deep scan.",
                evidence={"keyword": kw.decode('ascii', errors='replace'), "malicious_text": kw.decode('ascii', errors='replace')},
                confidence=0.45,
                module="fast_scan.pdf.keywords"
            ))

    # 2b. Stealth Characters (Obfuscation)
    for char_bytes, name in STEALTH_CHARS:
        if char_bytes in data:
            findings.append(
                Finding(
                    threat_id=ThreatID.T3_OBFUSCATION,
                    # High enough to trigger deep scan (0.30 > 0.20)
                    severity=Severity.HIGH,
                    title=f"Suspicious Hidden Character ({name})",
                    explain=(
                        f"Found {name} in raw stream, often used for "
                        "stealth injections."
                    ),
                    evidence={"char": name},
                    module="fast_scan.pdf.stealth",
                )
            )
            # DISABLED: Do not cross-pollinate T4 verdicts here. T3 is sufficient.
            # Also flag as potential T4
            # findings.append(Finding(
            #     threat_id=ThreatID.T4_PROMPT_INJECTION,
            #     # ...
            # ))

    # 1b. Pre-processed scan: decode hex-encoded strings and line continuations,
    # then re-scan for active-content tokens that evade exact byte matching.
    processed = _preprocess_pdf_bytes(data)
    if processed != data:
        data_lower_proc = processed.lower()
        for token in SUSPICIOUS_TOKENS:
            if token in processed and token not in data:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="Hex-Encoded/Split Active PDF Token: {}".format(
                            token.decode("ascii", errors="ignore")
                        ),
                        explain=(
                            "Active-content token '{}' found only after hex-decoding "
                            "or joining split lines — a known evasion technique.".format(
                                token.decode("ascii", errors="ignore")
                            )
                        ),
                        evidence={"token": token.decode("ascii", errors="ignore"),
                                  "evasion": "hex_or_split"},
                        confidence=0.85,
                        module="fast_scan.pdf.hex_tokens",
                    )
                )

    # 1c. FlateDecode decompressed scan — active-content tokens hidden in
    # compressed streams are invisible to raw-byte scanning.
    if b"FlateDecode" in data:
        decompressed = _decompress_flate_streams(data)
        if decompressed:
            for token in SUSPICIOUS_TOKENS:
                if token in decompressed:
                    sev = Severity.MEDIUM
                    if token in [b"/OpenAction", b"/Launch", b"/Encrypt"]:
                        sev = Severity.HIGH
                    findings.append(
                        Finding(
                            threat_id=(
                                ThreatID.T2_ACTIVE_CONTENT
                                if token != b"/Encrypt"
                                else ThreatID.T3_OBFUSCATION
                            ),
                            severity=sev,
                            title="Active PDF Token in FlateDecode Stream: {}".format(
                                token.decode("ascii", errors="ignore")
                            ),
                            explain=(
                                "Found '{}' inside a FlateDecode-compressed PDF "
                                "stream. Compression hides tokens from raw-byte "
                                "scanners.".format(token.decode("ascii", errors="ignore"))
                            ),
                            evidence={"token": token.decode("ascii", errors="ignore"),
                                      "evasion": "flate_compressed"},
                            confidence=0.85,
                            module="fast_scan.pdf.flate_tokens",
                        )
                    )
            # Also scan decompressed bytes for injection keywords
            dec_lower = decompressed.lower()
            for kw in config.prompt_injection_keywords_bytes:
                if kw in dec_lower:
                    findings.append(Finding(
                        threat_id=ThreatID.T4_PROMPT_INJECTION,
                        severity=Severity.MEDIUM,
                        title="Prompt Injection Keyword in Compressed PDF Stream",
                        explain=(
                            f"Injection keyword '{kw.decode('ascii', errors='replace')}' "
                            "found inside a FlateDecode-compressed stream."
                        ),
                        evidence={"keyword": kw.decode("ascii", errors="replace"),
                                  "evasion": "flate_compressed"},
                        confidence=0.65,
                        module="fast_scan.pdf.flate_keywords",
                    ))
                    break

    # 2c. White-on-White Stealth Text (Obfuscation / Hidden Content)
    # rg = non-stroking (fill) color; RG = stroking color.
    # Covers integer (1 1 1), float (1.0 1.0 1.0) and trailing-dot (1. 1. 1.) forms.
    _WHITE_OP_RE = re.compile(rb"1\.?0?\s+1\.?0?\s+1\.?0?\s+[rR][gG]")
    if _WHITE_OP_RE.search(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF White-on-White Stealth Text",
                explain=(
                    "Detected white color operator in PDF content stream. "
                    "Text rendered in white on white background is invisible "
                    "to humans but readable by parsers — a common technique "
                    "for hiding adversarial content."
                ),
                evidence={"malicious_text": "White-on-white text operator detected in stream"},
                confidence=0.90,
                module="fast_scan.pdf.stealth",
            )
        )

    # 2d. Invisible Text Rendering Mode (3 Tr)
    # PDF text rendering mode 3 = invisible (clips path but draws nothing).
    # Attackers use `3 Tr` to embed text that is absent from the screen but
    # fully parsed by PDF readers and ATS systems.
    _TR3_RE = re.compile(rb'(?<![0-9])3\s+Tr\b')
    if _TR3_RE.search(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF Invisible Text Rendering Mode (3 Tr)",
                explain=(
                    "Detected PDF text rendering mode 3 ('3 Tr'). "
                    "Invisible text is not shown on screen but is present "
                    "in the byte stream and readable by parsers."
                ),
                evidence={"malicious_text": "Invisible text rendering mode (3 Tr) detected"},
                confidence=0.90,
                module="fast_scan.pdf.stealth",
            )
        )

    # 2e. Sub-1pt Font Size (Tf operator)
    # `/FontName 0.NNN Tf` — a font size < 1pt is effectively invisible.
    _TINY_TF_RE = re.compile(rb'/\w+\s+0\.\d+\s+Tf\b')
    if _TINY_TF_RE.search(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF Near-Zero Font Size (Tf)",
                explain=(
                    "Detected a sub-1pt font size in a PDF Tf operator. "
                    "Text at near-zero size is invisible to human readers "
                    "but fully extracted by parsers."
                ),
                evidence={"malicious_text": "Near-zero font size Tf operator detected"},
                confidence=0.85,
                module="fast_scan.pdf.stealth",
            )
        )

    # 2f. CMYK White Text — `0 0 0 0 k` (all-zero CMYK = white in subtractive
    # colour model).  Not caught by the RGB `1 1 1 rg` pattern above.
    _CMYK_WHITE_RE = re.compile(rb"0\s+0\s+0\s+0\s+[kK]\b")
    if _CMYK_WHITE_RE.search(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF CMYK White Text (0 0 0 0 k)",
                explain=(
                    "Detected all-zero CMYK colour operator ('0 0 0 0 k'). "
                    "In the subtractive colour model this renders text white on "
                    "white paper — invisible to readers but parsed by ATS/LLM tools."
                ),
                evidence={"malicious_text": "CMYK white operator (0 0 0 0 k) detected"},
                confidence=0.85,
                module="fast_scan.pdf.stealth",
            )
        )

    # 2g. Clipping-Path Invisible Text — `W n` operators define a zero-area
    # clipping region before text operators, hiding content from display while
    # keeping it parseable.
    _CLIP_PATH_RE = re.compile(rb"W\s+n\s*(?=.*?BT\b)", re.DOTALL)
    if _CLIP_PATH_RE.search(data[:config.limits.fast_pdf_token_scan_mb * 1024 * 1024]):
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.MEDIUM,
                title="PDF Clipping-Path Invisible Text (W n)",
                explain=(
                    "Detected 'W n' (clip-path + no-paint) operator before a text "
                    "block. This renders text into an empty clipping region, making "
                    "it invisible on screen while remaining extractable by parsers."
                ),
                evidence={"malicious_text": "Clipping-path invisible text (W n ... BT)"},
                confidence=0.75,
                module="fast_scan.pdf.stealth",
            )
        )

    # D.14: PDF page-tree cycle detection.  /Type /Pages nodes can declare
    # `/Kids` arrays that include their own parent → infinite recursion in
    # pikepdf / pdfminer.  Walk the page-tree subgraph independently of the
    # XObject cycle scan.
    if config.enable_dos_checks:
        try:
            from ...utils.graph_cycle import has_cycle as _has_cycle
            _PAGES_HEADER_RE = re.compile(
                rb"(\d+)\s+0\s+obj\b[^a-zA-Z]*?/Type\s*/Pages\b", re.DOTALL,
            )
            _KIDS_RE = re.compile(rb"/Kids\s*\[([^\]]{0,4096})\]")
            _KID_REF_RE = re.compile(rb"(\d+)\s+0\s+R")
            page_graph: dict[int, list[int]] = {}
            for hm in _PAGES_HEADER_RE.finditer(data):
                obj_num = int(hm.group(1))
                # Look at the next 8 KB after the header for the /Kids array
                body = data[hm.end(): hm.end() + 8192]
                kids_m = _KIDS_RE.search(body)
                if not kids_m:
                    continue
                kids = [int(r.group(1)) for r in _KID_REF_RE.finditer(kids_m.group(1))]
                page_graph[obj_num] = kids
                if len(page_graph) > 200:
                    break  # bomb-PDF guard
            if page_graph and _has_cycle(page_graph):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="PDF Page-Tree Cycle (DoS)",
                        explain=(
                            "Detected a cycle in the PDF page-tree reference "
                            "graph (/Type /Pages → /Kids). Cycles cause "
                            "infinite recursion in PDF renderers and parsers."
                        ),
                        evidence={
                            "subtype": "page_tree_cycle",
                            "nodes": len(page_graph),
                            "malicious_text": "PDF page-tree cycle",
                        },
                        confidence=0.90,
                        module="fast_scan.pdf.page_tree",
                    )
                )
        except Exception:
            pass

    # 2h. Circular Form XObject Detection (DoS) — Form XObjects that reference
    # each other in a cycle cause infinite recursion in PDF renderers/parsers.
    if config.enable_dos_checks and _detect_xobject_cycles(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T6_DOS,
                severity=Severity.HIGH,
                title="PDF Circular Form XObject Reference (DoS)",
                explain=(
                    "Detected a cycle in the PDF Form XObject reference graph. "
                    "A Form XObject referencing itself (directly or indirectly) "
                    "causes infinite recursion in PDF renderers and document parsers."
                ),
                evidence={"malicious_text": "Circular XObject reference cycle detected"},
                confidence=0.90,
                module="fast_scan.pdf.dos",
            )
        )

    # 2i. Annotation-embedded JavaScript (B.2) — /Subtype /JavaScript in an
    # action dictionary inside /Annots executes on user interaction (hover,
    # click, focus).  The token scan catches /JS but misses the /Subtype form.
    if config.enable_active_content_checks:
        _ANNOT_JS_RE = re.compile(rb"/(?:S|Subtype)\s*/JavaScript\b")
        if _ANNOT_JS_RE.search(data):
            findings.append(
                Finding(
                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                    severity=Severity.HIGH,
                    title="JavaScript in PDF Annotation Action",
                    explain=(
                        "Detected /Subtype /JavaScript inside a PDF action dictionary. "
                        "Annotation-embedded JavaScript runs when a user interacts "
                        "with the annotation and is a common exploit delivery vector."
                    ),
                    evidence={"malicious_text": "/Subtype /JavaScript in annotation"},
                    confidence=0.85,
                    module="fast_scan.pdf.annots",
                )
            )

        # B.13: /AA (Additional Actions) sub-key check — /AA is caught by
        # SUSPICIOUS_TOKENS but sub-keys (/S /JavaScript, /S /Launch,
        # /S /GoToR, /S /URI) are not.  These fire on page open/close, field
        # focus/blur, and keystroke events — not only on document open.
        if b"/AA" in data:
            _AA_SUBKEY_RE = re.compile(
                rb"/AA\b.{0,500}/S\s*/(?:JavaScript|Launch|GoToR|URI)\b", re.DOTALL
            )
            _aa_m = _AA_SUBKEY_RE.search(data)
            if _aa_m:
                _S_TYPE_RE = re.compile(rb"/S\s*/(\w+)\b")
                s_match = _S_TYPE_RE.search(_aa_m.group(0))
                action_type = (
                    s_match.group(1).decode("ascii", errors="replace")
                    if s_match else "Unknown"
                )
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title=f"PDF /AA Additional Action: /{action_type}",
                        explain=(
                            f"Detected /AA (Additional Actions) dictionary with "
                            f"/S /{action_type} sub-action. Additional actions "
                            "fire on page open/close, field focus/blur, and "
                            "keystroke events — not just on document open."
                        ),
                        evidence={
                            "malicious_text": f"/AA /S /{action_type} detected",
                            "action_type": action_type,
                        },
                        confidence=0.85,
                        module="fast_scan.pdf.aa_actions",
                    )
                )

    # 2j. PDF Incremental Update Layers (B.3) — multiple %%EOF markers indicate
    # incremental saves.  Attackers use this to overlay a "clean" top layer over
    # malicious content that persists in earlier byte ranges (PDF shadow attack).
    # Marked INFO because the *count* alone is uninformative — any PDF that's
    # been edited and saved more than once has 2+ %%EOFs. A genuine shadow
    # attack requires correlated divergent content across layers, which is a
    # separate detector. Kept in the report for auditors who want to see it.
    eof_count = data.count(b"%%EOF")
    if eof_count > 1 and config.enable_obfuscation_checks:
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.LOW,
                title="PDF Incremental Update Layers",
                explain=(
                    f"Detected {eof_count} %%EOF markers indicating incremental "
                    "update layers. Legitimate for any document that has been "
                    "edited and re-saved (or carries a digital signature). "
                    "Recorded for audit only — not a verdict driver."
                ),
                evidence={"eof_count": eof_count},
                confidence=0.65,
                module="fast_scan.pdf.structure",
                verdict_class=VerdictClass.INFO,
            )
        )

    # 2k. Password-Protected PDF (B.8) — an /Encrypt indirect reference
    # (/Encrypt X Y R) signals real encryption.  The scanner cannot access
    # plaintext; flag T1 MEDIUM so reviewers know the scan is incomplete.
    _ENCRYPT_REF_RE = re.compile(rb"/Encrypt\s+\d+\s+\d+\s+R\b")
    if _ENCRYPT_REF_RE.search(data):
        findings.append(
            Finding(
                threat_id=ThreatID.T1_MALWARE,
                severity=Severity.MEDIUM,
                title="Password-Protected PDF (Scan Incomplete)",
                explain=(
                    "PDF contains an /Encrypt dictionary reference, indicating "
                    "password protection or DRM. Encrypted content cannot be "
                    "fully scanned; treat as unverified."
                ),
                evidence={"malicious_text": "/Encrypt indirect reference found"},
                confidence=0.80,
                module="fast_scan.pdf.encrypt",
            )
        )

    # 2l. PDF Optional Content Groups — B.4
    # /OCProperties signals the PDF uses layers.  Attackers mark groups as
    # hidden (/OFF) to conceal injection text from viewers while keeping it
    # parseable by text-extraction tools and LLMs.
    if config.enable_obfuscation_checks and b"/OCProperties" in data:
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.MEDIUM,
                title="PDF Optional Content Groups (Hidden Layers)",
                explain=(
                    "PDF contains /OCProperties, indicating Optional Content "
                    "Groups (layers). Attackers configure layers as hidden (/OFF) "
                    "so injection text is invisible in viewers but fully extracted "
                    "by parsers and LLMs."
                ),
                evidence={"malicious_text": "/OCProperties detected"},
                confidence=0.65,
                module="fast_scan.pdf.ocg",
            )
        )

    # 2m. PDF Annotation /Contents keyword scan — B.5 + E.4
    # Annotation text strings (/Contents inside /Annots) are extracted by
    # PyMuPDF / pdfplumber and consumed by LLMs.  They are outside the body-
    # text scan area and form an entirely unscanned injection surface.
    # E.4: extended subtypes — Stamp, Caret, FreeText, Polygon, PolyLine,
    # Ink, Squiggly, Underline, StrikeOut, Highlight all carry /Contents.
    if config.enable_prompt_injection:
        _CONTENTS_RE = re.compile(rb"/Contents\s*\(([^)]{10,500})\)")
        _ANNOT_NEARBY_RE = re.compile(
            rb"/Subtype\s*/(?:Text|Widget|FreeText|Stamp|Caret|Polygon|"
            rb"PolyLine|Ink|Squiggly|Underline|StrikeOut|Highlight|Sound|"
            rb"FileAttachment|Popup)\b"
        )
        for _cm in _CONTENTS_RE.finditer(data):
            ann_text_bytes = _cm.group(1)
            ann_text_lower = ann_text_bytes.lower()
            # Only scan if this /Contents appears near an annotation marker
            ctx_start = max(0, _cm.start() - 400)
            ctx = data[ctx_start : _cm.start()]
            if not _ANNOT_NEARBY_RE.search(ctx):
                continue
            for kw in config.prompt_injection_keywords_bytes:
                if kw in ann_text_lower:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T4_PROMPT_INJECTION,
                            severity=Severity.HIGH,
                            title="Prompt Injection in PDF Annotation Text",
                            explain=(
                                "Detected injection keyword in a PDF /Annots /Contents "
                                "string. Annotation text is extracted by most PDF tools "
                                "and LLMs but is outside the body-text scan area."
                            ),
                            evidence={
                                "subtype": "annotation_contents",
                                "keyword": kw.decode("ascii", errors="replace"),
                                "malicious_text": ann_text_bytes[:250].decode(
                                    "ascii", errors="replace"
                                ),
                            },
                            confidence=0.80,
                            module="fast_scan.pdf.annotations",
                        )
                    )
                    break  # one finding per annotation

        # E.4: AcroForm field default values — /V (current value) and /DV
        # (default value). Adobe Reader prefills these so an LLM that
        # extracts form-state sees them. Body-text and /Contents scans miss
        # them entirely.
        _FIELD_VALUE_RE = re.compile(
            rb"/(?:V|DV)\s*\(([^)]{10,800})\)"
        )
        _FIELD_NEARBY_RE = re.compile(
            rb"/(?:T|FT|Ff|Kids|Parent|AA)\s*[(/<\[]"
        )
        seen_field_kws: set[bytes] = set()
        for _vm in _FIELD_VALUE_RE.finditer(data):
            fld_text_bytes = _vm.group(1)
            fld_text_lower = fld_text_bytes.lower()
            ctx_start = max(0, _vm.start() - 500)
            ctx = data[ctx_start: _vm.start()]
            if not _FIELD_NEARBY_RE.search(ctx):
                continue
            for kw in config.prompt_injection_keywords_bytes:
                if kw in fld_text_lower and kw not in seen_field_kws:
                    seen_field_kws.add(kw)
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T4_PROMPT_INJECTION,
                            severity=Severity.HIGH,
                            title="Prompt Injection in PDF AcroForm Field Default",
                            explain=(
                                "Injection keyword found in an AcroForm field's "
                                "/V (current value) or /DV (default value). PDF "
                                "viewers prefill these on render and LLM document "
                                "loaders include them in extracted form state."
                            ),
                            evidence={
                                "subtype": "acroform_field_default",
                                "keyword": kw.decode("ascii", errors="replace"),
                                "malicious_text": fld_text_bytes[:250].decode(
                                    "ascii", errors="replace"
                                ),
                            },
                            confidence=0.85,
                            module="fast_scan.pdf.acroform",
                        )
                    )
                    break

    # 3. V2 Multi-Signal Obfuscation Logic
    signals = []

    # Signal A: Object Density
    obj_count = data.count(b" obj")
    if obj_count >= 1500:  # Lowered threshold for signal
        signals.append("high_obj_count")

    # 4. DoS Checks (Added for T6) - Production Generalization
    # Instead of a hard threshold (e.g. > 3000), we use Density (Objects/Page)
    # to distinguish between "Valid Large Doc" (many pages) and "PDF Bomb"
    # (few pages, massive objects).

    # Attempt to extract page count
    page_match = re.search(rb"/Type\s*/Pages\s*/Count\s+(\d+)", data)
    if not page_match:
        page_match = re.search(rb"/Count\s+(\d+)", data)

    page_count = 1  # Default to 1 to be conservative (assume high density if unknown)
    if page_match:
        try:
            page_count = int(page_match.group(1))
            if page_count < 1:
                page_count = 1
        except Exception:
            page_count = 1

    # Heuristics:
    # 1. Absolute Sanity Limit: from config.limits
    # 2. Density Threshold: > max_objects / default pages logic
    is_dos_suspect = False

    if obj_count > getattr(config.limits, "max_objects", 25000):
        is_dos_suspect = True
    elif obj_count > 3000 and (obj_count / page_count) > (
        getattr(config.limits, "max_objects", 3000) / 4
    ):
        is_dos_suspect = True

    if is_dos_suspect:
        findings.append(
            Finding(
                threat_id=ThreatID.T6_DOS,
                severity=Severity.HIGH,
                title="Suspicious Object Density (DoS)",
                explain=(
                    f"High object density detected: {obj_count} objects across "
                    f"{page_count} pages ({int(obj_count / page_count)} obj/page)."
                ),
                evidence={
                    "obj_count": obj_count,
                    "page_count": page_count,
                    "density": obj_count / page_count,
                },
                module="fast_scan.pdf.dos",
            )
        )

    # Clean up old density check logic to avoid duplication
    if page_match and not is_dos_suspect:
        try:
            if page_count > getattr(config.limits, "max_pages", 2000):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="High Page Count (DoS)",
                        explain=f"Detected page count {page_count}, potential DoS.",
                        evidence={"page_count": page_count},
                        module="fast_scan.pdf.dos",
                    )
                )
        except Exception as e:
            logger.debug("Error checking page count: %s", e)

    # Signal B: Filter Count
    filter_count = data.count(b"/Filter")
    if filter_count >= 30:
        signals.append("high_filter_count")

    # Signal C: Entropy
    ent = _byte_entropy(data)
    if ent >= 7.95 and len(data) >= 1024 * 1024:
        signals.append("high_entropy")

    # Decision
    if len(signals) >= 2:
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF Obfuscation Detected (Multi-Signal)",
                explain=(
                    f"Detected multiple obfuscation indicators: {', '.join(signals)}."
                ),
                evidence={
                    "signals": signals,
                    "obj_count": obj_count,
                    "filter_count": filter_count,
                    "entropy": ent,
                },
                module="fast_scan.pdf.obfuscation",
            )
        )

    return findings
