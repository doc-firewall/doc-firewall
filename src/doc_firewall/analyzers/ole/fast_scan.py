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
import re
from typing import List

from ...config import ScanConfig
from ...enums import ThreatID, Severity
from ...report import Finding
from ...logger import get_logger

logger = get_logger()

try:
    import olefile  # type: ignore
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False


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


def scan_ole_container(file_path: str, config: ScanConfig) -> List[Finding]:
    """Top-level OLE2 / CFB scan.  Use for legacy .doc/.xls/.ppt and for
    extracted vbaProject.bin from OOXML files.
    """
    findings: List[Finding] = []

    if not _HAS_OLEFILE:
        logger.debug("olefile not installed; OLE scanner skipped")
        return findings

    try:
        ole = olefile.OleFileIO(file_path)
    except Exception as exc:
        logger.debug("Not a valid OLE2 container (%s): %s", file_path, exc)
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
    if not _HAS_OLEFILE:
        return []
    try:
        data = zf.read(member_name)
    except Exception:
        return []
    if not data.startswith(_CFB_MAGIC):
        return []
    # olefile accepts a BytesIO
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
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
]
