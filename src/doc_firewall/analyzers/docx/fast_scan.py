from __future__ import annotations
import re
import zipfile
from typing import List
from ...enums import ThreatID, Severity, VerdictClass
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()



STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]

# Regexes for filtering external-relationship targets in fast_scan_docx.
# Mirror docx/external_refs.py — kept here to avoid circular import.
_REL_TARGET_RE = re.compile(rb'Target="([^"]+)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Target="([^"]+)"')
_REL_BENIGN_SCHEME_RE = re.compile(rb"^(?:https?|mailto|tel|sms):", re.IGNORECASE)
_REL_IP_LITERAL_RE = re.compile(rb"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
_REL_SUSPICIOUS_SCHEME_RE = re.compile(rb"^(?:javascript|data|vbscript|file|jar|ftp|smb):", re.IGNORECASE)


def _first_suspicious_rel_target(rel_content: bytes) -> str | None:
    """Return the first external-rel Target that uses a non-standard scheme,
    an IP-literal host, or is scheme-less. None if all targets are benign."""
    for m in _REL_TARGET_RE.finditer(rel_content):
        target = (m.group(1) or m.group(2) or b"").strip()
        if not target:
            continue
        if _REL_SUSPICIOUS_SCHEME_RE.match(target) or _REL_IP_LITERAL_RE.match(target):
            return target.decode("latin-1", errors="replace")[:300]
        if not _REL_BENIGN_SCHEME_RE.match(target) and b"://" not in target:
            return target.decode("latin-1", errors="replace")[:300]
    return None

# ── Hidden-text XML patterns (H1) ────────────────────────────────────────────
# All patterns applied to raw document.xml bytes.

# 1. <w:vanish/> — font property that makes a run invisible to the reader
_VANISH_RE = re.compile(rb"<w:vanish\b[^/]*/?>")

# 2. White-on-white: <w:color w:val="FFFFFF"/> (and near-white 6-hex values
#    where all channels are EE–FF, e.g. FFFFFE / EEFFEE)
#    Pattern: any 6-hex string composed entirely of E or F digits (covers
#    R,G,B ≥ 0xEE = 238/255 ≈ 93% brightness — invisible on white pages).
_WHITE_COLOR_RE = re.compile(rb'<w:color\s+w:val="([EF]{6})"\s*/?>', re.IGNORECASE)

# 3. Zero / near-zero font size: <w:sz w:val="N"/> where N ≤ 4 (≤ 2 pt;
#    OOXML uses half-points, so 4 = 2pt, 2 = 1pt, 1 = 0.5pt)
_TINY_FONT_RE = re.compile(rb'<w:sz\s+w:val="([0-4])"\s*/?>')

# 4. Off-page vertical positioning: <w:position w:val="N"/> where |N| ≥ 1440
#    (OOXML uses half-points: 1440 half-pts = 720pt ≈ 10 inches off the page)
_OFFPAGE_POS_RE = re.compile(rb'<w:position\s+w:val="(-?\d+)"\s*/?>')

# Capture <w:t...>BODY</w:t> for run-text extraction.
_W_TEXT_RE = re.compile(rb"<w:t(?:\s[^>]*)?>([^<]*)</w:t>")


def _extract_run_text(content: bytes, pos: int, limit: int = 250) -> str:
    """Return concatenated <w:t> text inside the <w:r>...</w:r> run that
    contains `pos` (the start of a hidden-text marker match). Empty string
    if the run boundaries can't be located."""
    open_a = content.rfind(b"<w:r ", 0, pos)
    open_b = content.rfind(b"<w:r>", 0, pos)
    run_open = max(open_a, open_b)
    if run_open < 0:
        return ""
    tag_close = content.find(b">", run_open, run_open + 200)
    if tag_close < 0:
        return ""
    run_end = content.find(b"</w:r>", pos)
    if run_end < 0:
        return ""
    body = content[tag_close + 1 : run_end]
    parts = [m.group(1).decode("utf-8", errors="replace")
             for m in _W_TEXT_RE.finditer(body)]
    return "".join(parts).strip()[:limit]


def _check_hidden_text_xml(content: bytes) -> list[tuple[str, str, str]]:
    """Return a list of (technique, detail, hidden_text) tuples for any
    hidden-text patterns found in raw document.xml bytes. `hidden_text`
    is the actual text content of the affected <w:r> run (empty if the
    run text could not be extracted)."""
    hits: list[tuple[str, str, str]] = []

    m = _VANISH_RE.search(content)
    if m:
        hits.append(("vanish", "<w:vanish/> property found",
                     _extract_run_text(content, m.start())))

    m = _WHITE_COLOR_RE.search(content)
    if m:
        hits.append(("white_color", f"white text color: #{m.group(1).decode()}",
                     _extract_run_text(content, m.start())))

    m = _TINY_FONT_RE.search(content)
    if m:
        half_pts = int(m.group(1))
        pts = half_pts / 2
        hits.append(("tiny_font", f"font size {pts}pt (≤2pt threshold)",
                     _extract_run_text(content, m.start())))

    m = _OFFPAGE_POS_RE.search(content)
    if m:
        val = int(m.group(1))
        if abs(val) >= 1440:
            hits.append(("offpage", f"extreme vertical position: {val} half-pts",
                         _extract_run_text(content, m.start())))

    return hits

_CFB_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def fast_scan_docx(file_path: str, config: ScanConfig) -> List[Finding]:
    findings = []

    # B.8: Password-protected Office file — encrypted DOCX/XLSX/PPTX files are
    # wrapped in an OLE2 CFB container instead of a ZIP archive.  The scanner
    # cannot read the plaintext; flag T1 MEDIUM so reviewers know the scan is
    # incomplete.
    try:
        with open(file_path, "rb") as _f:
            _magic = _f.read(8)
        if _magic == _CFB_MAGIC:
            findings.append(
                Finding(
                    threat_id=ThreatID.T1_MALWARE,
                    severity=Severity.MEDIUM,
                    title="Password-Protected Office Document (Encrypted CFB)",
                    explain=(
                        "File is wrapped in an encrypted OLE2/CFB container, "
                        "indicating password protection. Content cannot be scanned; "
                        "treat as unverified."
                    ),
                    evidence={"malicious_text": "OLE2/CFB magic bytes — file is encrypted"},
                    confidence=0.90,
                    module="fast_scan.docx.encrypt",
                )
            )
            return findings
    except OSError:
        return findings

    if not zipfile.is_zipfile(file_path):
        return findings

    with zipfile.ZipFile(file_path, "r") as zf:
        infolist = zf.infolist()

        part_count = len(infolist)
        total_uncompressed = sum(z.file_size for z in infolist)
        total_compressed = sum(z.compress_size for z in infolist)
        overall_ratio = (
            (total_uncompressed / total_compressed) if total_compressed > 0 else 0
        )

        # 1. Zip Bomb / DoS Checks — return immediately on hard structural limits
        # so we never iterate thousands of parts in a confirmed DoS document.
        total_mb = total_uncompressed / (1024 * 1024)

        if part_count > config.limits.max_docx_parts:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many DOCX parts",
                    explain=(
                        f"File contains {part_count} parts (limit "
                        f"{config.limits.max_docx_parts})."
                    ),
                    evidence={
                        "part_count": part_count,
                        "limit": config.limits.max_docx_parts,
                        "malicious_text": f"{part_count} parts",
                    },
                    module="fast_scan.docx.structure",
                )
            )
            if overall_ratio > config.limits.max_docx_overall_expansion_ratio:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="Suspicious Compression Ratio",
                        explain=(
                            f"Compression ratio {overall_ratio:.0f}x exceeds limit "
                            f"{config.limits.max_docx_overall_expansion_ratio}x — "
                            "zip-bomb pattern."
                        ),
                        evidence={
                            "overall_ratio": round(overall_ratio, 2),
                            "malicious_text": f"ratio {overall_ratio:.0f}x",
                        },
                        module="fast_scan.docx.structure",
                    )
                )
            return findings  # confirmed DoS — skip per-part iteration

        if total_mb > config.limits.max_docx_total_uncompressed_mb:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Total uncompressed size too large",
                    explain=(
                        f"Uncompressed size {total_mb:.2f} MB exceeds limit "
                        f"{config.limits.max_docx_total_uncompressed_mb} MB."
                    ),
                    evidence={"size_mb": total_mb, "malicious_text": f"{total_mb:.1f} MB uncompressed"},
                    module="fast_scan.docx.structure",
                )
            )
            return findings  # confirmed DoS — skip per-part iteration

        suspicious_parts = 0

        # 2. Content Checks (VBA, Embeddings, Keywords)
        # Cap iteration to max_docx_parts to bound scan time even when the
        # part count is just under the limit.
        scan_limit = config.limits.max_docx_parts
        for z in infolist[:scan_limit]:
            # Zip Bomb heuristic
            if z.file_size > config.limits.max_docx_single_part_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Large individual XML part",
                        explain=(
                            f"Part {z.filename} is {z.file_size / 1024 / 1024:.2f} MB."
                        ),
                        evidence={
                            "filename": z.filename,
                            "size_mb": z.file_size / 1024 / 1024,
                        },
                        module="fast_scan.docx.structure",
                    )
                )

            ratio = z.file_size / z.compress_size if z.compress_size > 0 else 0
            if (
                ratio > getattr(config.limits, "max_docx_overall_expansion_ratio", 200)
                and z.file_size > 1024 * 1024
            ):
                suspicious_parts += 1

            # Macros
            if z.filename.endswith("vbaProject.bin") or "macrosheets" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="Macro/VBA Content Found",
                        explain=(
                            f"Found suspicious file '{z.filename}' indicating macros."
                        ),
                        evidence={"filename": z.filename},
                        module="fast_scan.docx.macros",
                    )
                )
                # D.1: scan the vbaProject.bin OLE2 container for stomping +
                # shell APIs.  Imported lazily to keep the dependency optional.
                if (
                    z.filename.endswith("vbaProject.bin")
                    and getattr(config, "enable_legacy_office", True)
                ):
                    try:
                        from ..ole.fast_scan import scan_embedded_vbaproject
                        findings.extend(
                            scan_embedded_vbaproject(zf, z.filename, config)
                        )
                    except Exception as _vba_e:
                        logger.debug("vbaProject scan failed: %s", _vba_e)

            # Embeddings
            if "word/embeddings/" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.MEDIUM,
                        title="Embedded Object Found",
                        explain=f"Found embedded object '{z.filename}'.",
                        evidence={"filename": z.filename},
                        confidence=0.65,
                        module="fast_scan.docx.ole",
                    )
                )
                # B.12: Check embedded file for suspicious extensions or nested
                # archives containing executables — a common dropper technique.
                _B12_SUSPICIOUS = {
                    "exe", "dll", "js", "ps1", "vbs", "bat", "cmd",
                    "hta", "jar", "py", "sh", "msi", "scr",
                }
                _emb_ext = (
                    z.filename.rsplit(".", 1)[-1].lower()
                    if "." in z.filename else ""
                )
                if _emb_ext in _B12_SUSPICIOUS:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.CRITICAL,
                            title=f"Suspicious Embedded File Extension (.{_emb_ext})",
                            explain=(
                                f"DOCX contains '{z.filename}' — a suspicious "
                                f"extension (.{_emb_ext}) used in dropper attacks."
                            ),
                            evidence={"filename": z.filename, "extension": _emb_ext},
                            confidence=0.90,
                            module="fast_scan.docx.embedded_archive",
                            # Embedded .exe/.dll/.ps1/.vbs/.bat/.hta etc.
                            # in a DOCX has no legitimate use — definitive.
                            verdict_class=VerdictClass.BLOCK,
                        )
                    )
                elif _emb_ext == "zip" and z.file_size < 8 * 1024 * 1024:
                    try:
                        import io as _io
                        with zf.open(z) as _emb_f:
                            _emb_data = _emb_f.read(8 * 1024 * 1024)
                        with zipfile.ZipFile(_io.BytesIO(_emb_data)) as _inner:
                            for _iname in _inner.namelist():
                                _iext = (
                                    _iname.rsplit(".", 1)[-1].lower()
                                    if "." in _iname else ""
                                )
                                if _iext in _B12_SUSPICIOUS:
                                    findings.append(
                                        Finding(
                                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                                            severity=Severity.HIGH,
                                            title="Suspicious File in Embedded Archive",
                                            explain=(
                                                f"Embedded archive '{z.filename}' "
                                                f"contains '{_iname}' (.{_iext})."
                                            ),
                                            evidence={
                                                "archive": z.filename,
                                                "member": _iname,
                                                "extension": _iext,
                                            },
                                            confidence=0.85,
                                            module="fast_scan.docx.embedded_archive",
                                        )
                                    )
                                    break
                    except Exception as _e:
                        logger.debug(
                            "Error reading embedded archive %s: %s", z.filename, _e
                        )

            # External Relationships — only flag when the target uses a
            # non-standard scheme (javascript:/data:/file:/vbscript:/jar:/
            # ftp:/smb:), an IP-literal host, or is scheme-less. Plain
            # http(s)/mailto/tel hyperlinks (resume contact links, embedded
            # https images) are not flagged. The deep-scan path in
            # docx/external_refs.py performs full XML parsing for the deep
            # report; this fast path is a regex guard.
            if z.filename.endswith(".rels"):
                try:
                    with zf.open(z) as f:
                        rel_content = f.read(512 * 1024)
                    if b'TargetMode="External"' in rel_content:
                        suspicious_target = _first_suspicious_rel_target(rel_content)
                        if suspicious_target:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                    severity=Severity.HIGH,
                                    title="DOCX External Relationship With Suspicious Target",
                                    explain=(
                                        f"In {z.filename}, an external "
                                        "relationship targets a non-standard "
                                        "scheme or IP-literal host."
                                    ),
                                    evidence={
                                        "filename": z.filename,
                                        "target": suspicious_target,
                                        "malicious_text": suspicious_target[:250],
                                    },
                                    confidence=0.85,
                                    module="fast_scan.docx.rels",
                                    # Mirrors docx/external_refs.py — definitive.
                                    verdict_class=VerdictClass.BLOCK,
                                )
                            )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # B.15: CustomXML parts scan — customXml/ parts are read by Office
            # automation and LLM document loaders but lie outside the body-text
            # scan area and are an unscanned injection surface.
            if z.filename.startswith("customXml/") and z.filename.endswith(".xml"):
                try:
                    with zf.open(z) as f:
                        xml_content = f.read(256 * 1024)
                    xml_lower = xml_content.lower()
                    for kw in config.prompt_injection_keywords_bytes:
                        if kw in xml_lower:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T4_PROMPT_INJECTION,
                                    severity=Severity.MEDIUM,
                                    title="Prompt Injection in DOCX CustomXML Part",
                                    explain=(
                                        f"Found injection keyword "
                                        f"'{kw.decode('ascii', errors='replace')}' "
                                        f"in {z.filename}. CustomXML parts are "
                                        "extracted by LLM document loaders but bypass "
                                        "body-text scanning."
                                    ),
                                    evidence={
                                        "keyword": kw.decode("ascii", errors="replace"),
                                        "filename": z.filename,
                                    },
                                    confidence=0.65,
                                    module="fast_scan.docx.customxml",
                                )
                            )
                            break  # one finding per customXml part
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # XML Entity Depth Check (T6 DoS) — item 0.9
            # defusedxml blocks XXE but not all entity-expansion attacks.
            # Check any XML part for <!ENTITY declarations with nested refs.
            if z.filename.endswith(".xml") and config.enable_dos_checks:
                try:
                    with zf.open(z) as f:
                        part_head = f.read(8192)  # DOCTYPE is always in the preamble
                    if b"<!ENTITY" in part_head:
                        # Count nesting depth: entities that reference other entities
                        entity_defs = re.findall(rb'<!ENTITY\s+\S+\s+"([^"]*)"', part_head)
                        max_depth = max(
                            (d.count(b"&") for d in entity_defs), default=0
                        )
                        if max_depth > 3:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T6_DOS,
                                    severity=Severity.HIGH,
                                    title="XML Entity Expansion (Billion Laughs)",
                                    explain=(
                                        f"Part '{z.filename}' declares XML entities "
                                        f"with nesting depth {max_depth} — a "
                                        "quadratic entity-expansion (billion-laughs) "
                                        "pattern that causes parser exhaustion."
                                    ),
                                    evidence={
                                        "filename": z.filename,
                                        "entity_depth": max_depth,
                                    },
                                    confidence=0.90,
                                    module="fast_scan.docx.dos",
                                )
                            )
                except Exception as e:
                    logger.debug("Error checking XML entities in %s: %s", z.filename, e)

            # Keyword Search in document.xml
            if z.filename == "word/document.xml":
                try:
                    # Read max 1MB of document.xml for speed
                    with zf.open(z) as f:
                        content = f.read(1024 * 1024)
                        content_lower = content.lower()
                        for kw in config.prompt_injection_keywords_bytes:
                            if kw in content_lower:
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T4_PROMPT_INJECTION,
                                        severity=Severity.MEDIUM,
                                        title="Potential Injection Keyword (Fast Scan)",
                                        explain=(
                                            f"Found keyword '{kw.decode('ascii', errors='replace')}' "
                                            "in document.xml."
                                        ),
                                        evidence={"keyword": kw.decode("ascii", errors="replace")},
                                        confidence=0.65,
                                        module="fast_scan.docx.keywords",
                                    )
                                )

                        # Check stealth chars
                        for char_bytes, name in STEALTH_CHARS:
                            if char_bytes in content:
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T3_OBFUSCATION,
                                        severity=Severity.HIGH,
                                        title=f"Suspicious Hidden Character ({name})",
                                        explain=(
                                            f"Found {name} in XML, "
                                            "possible stealth injection."
                                        ),
                                        evidence={"char": name},
                                        module="fast_scan.docx.stealth",
                                    )
                                )
                                # Also flag as potential T4
                                # since this is a common injection vector
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T4_PROMPT_INJECTION,
                                        severity=Severity.MEDIUM,
                                        title=(
                                            f"Potential Obfuscated Injection ({name})"
                                        ),
                                        explain=(
                                            f"Found {name}, commonly used "
                                            "to hide prompt injections."
                                        ),
                                        evidence={"char": name},
                                        module="fast_scan.docx.stealth",
                                    )
                                )

                        # ── H1: Extended hidden-text detection ────────────────
                        # Catches white-on-white, zero-size fonts, off-page
                        # positioning — techniques missed by vanish-only checks.
                        for technique, detail, hidden_text in _check_hidden_text_xml(content):
                            _TECHNIQUE_LABELS = {
                                "vanish": "Hidden Text (w:vanish)",
                                "white_color": "White-on-White Text",
                                "tiny_font": "Near-Zero Font Size",
                                "offpage": "Off-Page Text Positioning",
                            }
                            title = _TECHNIQUE_LABELS.get(technique, "Hidden Text")
                            evidence = {"technique": technique, "detail": detail}
                            if hidden_text:
                                evidence["hidden_text"] = hidden_text
                                evidence["malicious_text"] = hidden_text
                            else:
                                evidence["malicious_text"] = detail
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T3_OBFUSCATION,
                                    severity=Severity.HIGH,
                                    title=title,
                                    explain=(
                                        f"Detected hidden text technique in "
                                        f"document.xml: {detail}. Text may be "
                                        "invisible to readers but parsed by ATS "
                                        "systems."
                                    ),
                                    evidence=evidence,
                                    module="fast_scan.docx.hidden_text",
                                    confidence=0.90,
                                )
                            )

                except Exception as e:
                    logger.debug("Error reading document.xml: %s", e)

        if suspicious_parts >= 2 or (
            overall_ratio > config.limits.max_docx_overall_expansion_ratio
            and total_mb > 10
        ):
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Suspicious Compression Ratio",
                    explain=(
                        "High compression ratio detected, characteristic of Zip "
                        "Bombs or generated obfuscation."
                    ),
                    evidence={
                        "overall_ratio": round(overall_ratio, 2),
                        "suspicious_parts": suspicious_parts,
                    },
                    module="fast_scan.docx.structure",
                )
            )

    return findings
