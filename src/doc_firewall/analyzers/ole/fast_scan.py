"""D.1 + D.2: OLE2 / CFB (Compound File Binary) fast scanner.

Covers two threats v1.0 missed entirely:

  D.1  VBA stomping — `vbaProject.bin` (inside docm/xlsm/pptm OR a legacy
       .doc/.xls/.ppt) ships compiled P-code with the textual source
       stripped.  The YARA rules in `document_malware.yar` scan ASCII
       VBA source and miss P-code-only modules.

  D.2  Legacy Office binary formats (.doc / .xls / .ppt) — these are
       OLE2/CFB containers, not ZIP.  v1.0's magic-byte dispatcher only
       wired ZIP-based OOXML and PDF; legacy formats fell into the
       "unknown" path and were never deep-scanned.

Both checks are pure stdlib + the soft dependency `olefile`. If `olefile`
is not installed, the scanner returns no findings and logs a debug line —
it never raises.
"""
from __future__ import annotations

import io
from typing import List

from ...config import ScanConfig
from ...enums import Severity, ThreatID
from ...logger import get_logger
from ...report import Finding
from .cfb import CompoundFile

logger = get_logger()

try:
    import olefile  # type: ignore
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False


def _open_ole(src):
    """Open an OLE2/CFB container, preferring `olefile` when installed and
    falling back to the zero-dependency stdlib `CompoundFile` reader otherwise.

    `src` is a file path or a `BytesIO`.  Returns an object exposing the
    olefile-compatible subset (`listdir`, `openstream`, `close`), or `None`
    when the input is not a valid OLE2 container.  Never raises.
    """
    if _HAS_OLEFILE:
        try:
            return olefile.OleFileIO(src)
        except Exception:
            # A genuinely malformed container — fall through to the stdlib
            # reader, which is more permissive and still bounds-checked.
            pass
    try:
        return CompoundFile.open(src)
    except Exception:
        return None


# CFB / OLE2 magic bytes — the "Compound File Binary" header.  Same magic
# is used by .doc, .xls, .ppt, .msg, .vsd, AND by `vbaProject.bin` storage
# inside modern OOXML files (which is why this scanner also runs against
# extracted vbaProject.bin streams).
_CFB_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# Suspicious VBA / Office API strings to scan for in any binary stream.
_SUSPICIOUS_VBA_BYTES = [
    b"Shell", b"WScript.Shell", b"CreateObject", b"GetObject",
    b"Auto_Open", b"AutoExec", b"AutoOpen", b"Workbook_Open",
    b"Document_Open", b"Application.Run", b"CallByName",
    b"URLDownloadToFile", b"WinHttp", b"MSXML", b"ADODB.Stream",
    b"WMI", b"win32com", b"powershell",  b"cmd.exe",
    b"certutil", b"bitsadmin", b"regsvr32",
]

# Auto-run procedure names (trigger on document open/close without user interaction).
_VBA_AUTORUN_PROCS = frozenset({
    "autoopen", "auto_open", "document_open", "autoexec",
    "workbook_open", "auto_close", "document_close",
    "workbook_activate", "autoexit", "documentopen",
})

# High-risk APIs — network download or remote code execution; rare in benign macros.
_VBA_HIGH_RISK_APIS = frozenset({
    "urldownloadtofile", "winhttprequest", "msxml2.xmlhttp",
    "adodb.stream", "wscript.shell", "wshshell",
    "createprocessw", "virtualalloc",
})

# Medium-risk APIs — shell execution; also seen in legitimate automation macros.
_VBA_MEDIUM_RISK_APIS = frozenset({
    "shell ", "shell(", "shellexecute", "createobject(", "getobject(",
    "application.run", "callbyname",
    "powershell", "cmd.exe", "certutil", "bitsadmin",
    "regsvr32", "mshta", "wscript.exe", "cscript.exe",
})

# Non-source streams in VBA storage (P-code, project metadata, etc.).
_VBA_SYSTEM_STREAMS = frozenset({
    "_VBA_PROJECT", "dir", "PROJECT", "PROJECTwm",
})


def _vba_decompress(compressed: bytes) -> bytes:
    """MS-OVBA 2.4 decompression of a VBA module source stream.

    VBA stores module source code in a compressed format (OVBA compression)
    inside each module stream (e.g. ``Macros/VBA/Module1``).  The standard
    byte-level scan misses these because the source text is not readable in
    the raw stream.

    Returns the decompressed bytes, or empty bytes for invalid input.
    """
    if not compressed or compressed[0] != 0x01:
        return b""
    out = bytearray()
    i = 1
    while i < len(compressed):
        if i + 2 > len(compressed):
            break
        # CompressedChunkHeader: bits 0-11 = (chunk size - 3), bits 12-14 are a
        # fixed 0b011 signature, bit 15 = compressed flag.  A header without the
        # 0b011 signature (e.g. a zero/padding word after the real data) is not a
        # valid chunk and reliably marks the end of the compressed container.
        hdr = compressed[i] | (compressed[i + 1] << 8)
        if (hdr & 0x7000) != 0x3000:
            break
        i += 2
        chunk_data_bytes = (hdr & 0x0FFF) + 1   # bytes after the 2-byte header
        is_compressed = bool(hdr & 0x8000)
        chunk_end = min(i + chunk_data_bytes, len(compressed))
        if not is_compressed:
            # Raw (uncompressed) chunk — always exactly 4096 literal bytes.
            out.extend(compressed[i : i + 4096])
            i += 4096
        else:
            chunk_start = len(out)
            j = i
            while j < chunk_end:
                if j >= len(compressed):
                    break
                flag_byte = compressed[j]
                j += 1
                for bit in range(8):
                    if j >= chunk_end or j >= len(compressed):
                        break
                    if not (flag_byte >> bit) & 1:
                        # Literal byte.
                        out.append(compressed[j])
                        j += 1
                    else:
                        # CopyToken — 2 bytes encoding (offset, length) back-reference.
                        if j + 2 > len(compressed):
                            break
                        token = compressed[j] | (compressed[j + 1] << 8)
                        j += 2
                        # Bit split between the length and offset fields grows
                        # with how many bytes have been decompressed so far in
                        # this chunk (MS-OVBA 2.4.1.3.6 CopyToken): lb is 4 bits
                        # up to 16 bytes, then one more bit per power-of-two.
                        dcur = len(out) - chunk_start
                        lb = max(4, dcur.bit_length())
                        lm = (1 << lb) - 1
                        copy_len = (token & lm) + 3
                        copy_off = (token >> lb) + 1
                        src = len(out) - copy_off
                        if src < 0:
                            break
                        for _ in range(copy_len):
                            if src >= len(out):
                                break
                            out.append(out[src])
                            src += 1
            i = chunk_end
    return bytes(out)


def _vba_source_from_stream(data: bytes, max_scan: int = 65536) -> str:
    """Find and decompress VBA source code embedded in an OLE module stream.

    A VBA module stream is structured as ``[P-code bytes][0x01][compressed source]``.
    The P-code portion has no fixed length, so we scan for the 0x01 VBA compression
    signature followed by a valid compressed-chunk header and return the best result.
    """
    limit = min(len(data), max_scan)
    best = ""
    tries = 0
    for i in range(limit):
        if data[i] != 0x01:
            continue
        if i + 3 >= len(data):
            break
        # Quick-check: first chunk header must have the compressed flag set.
        hdr = data[i + 1] | (data[i + 2] << 8)
        if not (hdr & 0x8000):
            continue
        tries += 1
        if tries > 64:   # cap search cost for pathological streams
            break
        try:
            result = _vba_decompress(data[i:])
        except Exception:
            continue
        if len(result) < 20:
            continue
        # VBA source is ASCII — accept only outputs with high printable ratio.
        sample = result[:300]
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        ratio = printable / len(sample)
        if ratio > 0.70:
            text = result.decode("latin-1", errors="replace")
            if len(text) > len(best):
                best = text
                if ratio > 0.90:
                    break   # high confidence — stop scanning
    return best


def _extract_all_vba_sources(ole) -> list[str]:
    """Decompress and return VBA source text from all module streams in *ole*."""
    sources: list[str] = []
    try:
        all_streams = ole.listdir(streams=True, storages=False)
    except Exception:
        return sources
    for path in all_streams:
        if not path:
            continue
        # Only look inside VBA or Macros storages.
        path_upper = [p.upper() for p in path]
        if "VBA" not in path_upper and "MACROS" not in path_upper:
            continue
        last = path[-1]
        if (
            last in _VBA_SYSTEM_STREAMS
            or last.startswith("__SRP_")
            or last.startswith("PerformanceCache")
        ):
            continue
        try:
            with ole.openstream(path) as s:
                data = s.read(256 * 1024)   # 256 KB cap per module stream
        except Exception:
            continue
        text = _vba_source_from_stream(data)
        if text:
            sources.append(text)
    return sources


def _scan_ole_stream_bytes(data: bytes) -> list[str]:
    """Return any suspicious VBA / Office API strings found in `data`."""
    hits: list[str] = []
    lower = data.lower()
    for needle in _SUSPICIOUS_VBA_BYTES:
        if needle.lower() in lower:
            hits.append(needle.decode("ascii", errors="replace"))
    return hits


def _detect_vba_stomp(ole) -> tuple[bool, list[str]]:
    """D.1: detect P-code-only VBA modules.

    Returns (is_stomped, module_names) — True when at least one module's
    `PerformanceCache` (compiled P-code) stream is non-trivial but the
    corresponding source stream is empty / whitespace-only.
    """
    stomped_modules: list[str] = []
    # In OLE storage, each VBA module sits at e.g.:
    #   ['Macros', 'VBA', 'Module1']             (source stream)
    #   ['Macros', 'VBA', '_VBA_PROJECT_CUR', '__SRP_0']  (P-code cache)
    # Older / non-Word containers use ['VBA', 'Module1'].
    src_streams: list[list[str]] = []
    pcode_streams: list[list[str]] = []

    try:
        all_streams = ole.listdir(streams=True, storages=False)
    except Exception:
        return False, []

    for path in all_streams:
        if not path:
            continue
        last = path[-1]
        if last.startswith("__SRP_") or last.startswith("PerformanceCache"):
            pcode_streams.append(path)
        elif "VBA" in path and last not in (
            "_VBA_PROJECT", "dir", "PROJECT", "PROJECTwm",
        ):
            # Treat any other VBA-storage child as a candidate source stream
            src_streams.append(path)

    has_pcode = any(_nontrivial_stream(ole, p) for p in pcode_streams)
    if not has_pcode:
        return False, []

    # If we have P-code but no non-trivial source streams, that's the stomp.
    nontrivial_src = [
        p for p in src_streams if _nontrivial_stream(ole, p, min_size=256)
    ]
    if not nontrivial_src:
        stomped_modules = [p[-1] for p in pcode_streams[:5]]
        return True, stomped_modules

    return False, []


def _nontrivial_stream(ole, path: list[str], min_size: int = 8) -> bool:
    """Return True if the OLE stream at `path` is larger than `min_size` and
    not entirely whitespace / nulls."""
    try:
        with ole.openstream(path) as s:
            data = s.read(4096)
        if len(data) < min_size:
            return False
        # Strip nulls / whitespace and check residual length
        stripped = data.replace(b"\x00", b"").strip()
        return len(stripped) > 4
    except Exception:
        return False


def _check_vba_sources(sources: list[str]) -> List[Finding]:
    """Classify decompressed VBA source text and return threat findings.

    Separated from the OLE I/O layer so it can be tested without an OLE file.
    Detects three tiers:
      - AutoRun + high-risk download/network API → HIGH (dropper)
      - AutoRun + medium-risk shell API          → HIGH (dropper variant)
      - High-risk API without explicit AutoRun   → MEDIUM
    """
    if not sources:
        return []
    findings: List[Finding] = []
    all_src_lower = "\n".join(sources).lower()
    autorun = [p for p in _VBA_AUTORUN_PROCS if p in all_src_lower]
    hi_risk = [a for a in _VBA_HIGH_RISK_APIS if a in all_src_lower]
    med_risk = [a for a in _VBA_MEDIUM_RISK_APIS if a in all_src_lower]

    if autorun and hi_risk:
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.HIGH,
            title="VBA Macro Dropper: Auto-Execute + Download/Shell API",
            explain=(
                f"Document has a VBA macro that executes automatically on open "
                f"({', '.join(p.title() for p in autorun[:2])}) and calls "
                f"high-risk network/execution APIs ({', '.join(hi_risk[:2])}). "
                "This is the classic document dropper/downloader signature."
            ),
            evidence={
                "subtype": "vba_dropper",
                "autorun_procs": autorun[:5],
                "high_risk_apis": hi_risk[:5],
                "malicious_text": f"autorun={autorun[0]}; api={hi_risk[0]}",
            },
            confidence=0.90,
            module="ole.vba_source",
            mitre_technique="T1059.005",
            attack_objective="Silently execute payload when victim opens document",
        ))
    elif autorun and med_risk:
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.HIGH,
            title="VBA Macro: Auto-Execute + Shell API",
            explain=(
                f"VBA macro runs automatically on open "
                f"({', '.join(p.title() for p in autorun[:2])}) "
                f"and calls shell/process APIs ({', '.join(med_risk[:2])}). "
                "Common pattern in document-based malware; review the macro."
            ),
            evidence={
                "subtype": "vba_autorun_shell",
                "autorun_procs": autorun[:5],
                "shell_apis": med_risk[:5],
                "malicious_text": f"autorun={autorun[0]}; shell={med_risk[0]}",
            },
            confidence=0.80,
            module="ole.vba_source",
            mitre_technique="T1059.005",
            attack_objective="Execute system commands when victim opens document",
        ))
    elif hi_risk:
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.MEDIUM,
            title=f"VBA Macro: High-Risk Download/Execution API ({hi_risk[0]})",
            explain=(
                f"VBA macro uses high-risk network/download API: "
                f"{', '.join(hi_risk[:3])}. Frequently seen in dropper malware."
            ),
            evidence={
                "subtype": "vba_high_risk_api",
                "apis": hi_risk[:5],
                "malicious_text": hi_risk[0],
            },
            confidence=0.70,
            module="ole.vba_source",
            mitre_technique="T1059.005",
        ))
    return findings


def scan_ole_container(file_path: str, config: ScanConfig) -> List[Finding]:
    """Top-level OLE2 / CFB scan.  Use for legacy .doc/.xls/.ppt and for
    extracted vbaProject.bin from OOXML files.
    """
    findings: List[Finding] = []

    ole = _open_ole(file_path)
    if ole is None:
        logger.debug("Not a valid OLE2 container: %s", file_path)
        return findings

    try:
        # D.1: VBA stomping check
        stomped, modules = _detect_vba_stomp(ole)
        if stomped:
            findings.append(Finding(
                threat_id=ThreatID.T1_MALWARE,
                severity=Severity.HIGH,
                title="VBA Stomping — Compiled P-Code Without Source",
                explain=(
                    "OLE container has compiled VBA P-code "
                    f"({', '.join(modules) or 'unknown modules'}) but missing or "
                    "empty source streams. Classic VBA-stomping technique: the "
                    "P-code executes on open, the missing source defeats text-"
                    "based YARA / antivirus rules."
                ),
                evidence={
                    "subtype": "vba_stomp",
                    "stomped_modules": modules,
                    "malicious_text": "VBA stomping (P-code only)",
                },
                confidence=0.92,
                module="ole.vba_stomp",
                mitre_technique="T1027",
                attack_objective="Evade static VBA-source scanners via P-code-only macros",
            ))

        # D.2: scan every OLE stream for suspicious VBA / Office API strings
        all_streams = ole.listdir(streams=True, storages=False)
        seen: set[str] = set()
        for path in all_streams:
            try:
                with ole.openstream(path) as s:
                    stream_bytes = s.read(512 * 1024)  # cap at 512 KB / stream
            except Exception:
                continue
            hits = _scan_ole_stream_bytes(stream_bytes)
            for needle in hits:
                if needle in seen:
                    continue
                seen.add(needle)
                findings.append(Finding(
                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                    severity=Severity.HIGH,
                    title=f"OLE Stream Contains VBA / Shell API: {needle}",
                    explain=(
                        f"OLE stream {'/'.join(path)} contains '{needle}' — "
                        "a VBA macro API associated with shell execution / "
                        "code download. Common dropper signature."
                    ),
                    evidence={
                        "subtype": "ole_api_string",
                        "stream": "/".join(path),
                        "api": needle,
                        "malicious_text": needle,
                    },
                    confidence=0.80,
                    module="ole.api_strings",
                    mitre_technique="T1059.005",
                ))
            if len(seen) > 5:
                break  # avoid alert fatigue — five distinct APIs is plenty

        # D.3: Decompress VBA module streams and scan source for dropper patterns.
        # VBA source is compressed (MS-OVBA 2.4), so D.2's byte scan only catches
        # strings that survive in P-code binary; decompression catches the rest.
        findings.extend(_check_vba_sources(_extract_all_vba_sources(ole)))
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return findings


def fast_scan_ole(file_path: str, config: ScanConfig) -> List[Finding]:
    """Entry point for legacy .doc / .xls / .ppt fast scanning."""
    return scan_ole_container(file_path, config)


def scan_embedded_vbaproject(zf, member_name: str, config: ScanConfig) -> List[Finding]:
    """Scan a `vbaProject.bin` stream extracted from an OOXML ZIP container.

    `zf` is an open `zipfile.ZipFile`; `member_name` is the name of the entry.
    Writes the stream to a tmp file because olefile needs a path / file-like
    object that supports seek.
    """
    try:
        data = zf.read(member_name)
    except Exception:
        return []
    if not data.startswith(_CFB_MAGIC):
        return []
    ole = _open_ole(io.BytesIO(data))
    if ole is None:
        return []
    findings: List[Finding] = []
    try:
        stomped, modules = _detect_vba_stomp(ole)
        if stomped:
            findings.append(Finding(
                threat_id=ThreatID.T1_MALWARE,
                severity=Severity.HIGH,
                title="VBA Stomping in Embedded vbaProject.bin",
                explain=(
                    f"Embedded {member_name} contains compiled VBA P-code "
                    f"({', '.join(modules) or 'unknown modules'}) but missing "
                    "source streams. VBA stomping — P-code executes on open, "
                    "missing source defeats static scanners."
                ),
                evidence={
                    "subtype": "vba_stomp",
                    "vba_part": member_name,
                    "stomped_modules": modules,
                    "malicious_text": "VBA stomping (embedded)",
                },
                confidence=0.92,
                module="ole.vba_stomp",
                mitre_technique="T1027",
            ))
    finally:
        try:
            ole.close()
        except Exception:
            pass
    return findings


__all__ = [
    "fast_scan_ole",
    "scan_ole_container",
    "scan_embedded_vbaproject",
    "_CFB_MAGIC",
    "_vba_decompress",
    "_vba_source_from_stream",
    "_check_vba_sources",
]
