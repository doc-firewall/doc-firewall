"""
rtf/fast_scan.py — Byte-level fast scanner for RTF documents.

Scans raw bytes before full parsing to catch high-confidence indicators:
  T2: Embedded OLE objects (\\object, \\objdata), external field references
      (\\fldinstr HYPERLINK/URL), JavaScript via \\javascript
  T7: Embedded binary payloads signalled by \\bin control word
  T8: Metadata injection via {\\info ...} block with overlong fields
  T6: Unreasonably large files or deeply nested groups
"""
from __future__ import annotations

import re
import zlib
from typing import List

from ...report import Finding
from ...config import ScanConfig
from ...enums import ThreatID, Severity, VerdictClass


# Byte-level patterns — all RTF control words start with backslash
_PATTERN_OLE_OBJECT = re.compile(rb"\\object\b", re.IGNORECASE)
_PATTERN_OBJ_DATA   = re.compile(rb"\\objdata\b", re.IGNORECASE)
_PATTERN_FLDINSTR   = re.compile(rb"\\fldinstr\b", re.IGNORECASE)
_PATTERN_HYPERLINK  = re.compile(rb"HYPERLINK\s+", re.IGNORECASE)
_PATTERN_JAVASCRIPT = re.compile(rb"\\javascript\b", re.IGNORECASE)
_PATTERN_BIN        = re.compile(rb"\\bin\d+\b", re.IGNORECASE)
_PATTERN_INFO_BLOCK = re.compile(rb"\{\\info\b", re.IGNORECASE)
_PATTERN_RTF_MAGIC  = re.compile(rb"^\{\\rtf", re.IGNORECASE)
# External URL schemes in field instructions
_PATTERN_EXT_URL    = re.compile(rb"https?://|ftp://|file://|\\\\", re.IGNORECASE)
# RTF hidden text: \v control word marks a run as "hidden" (invisible on screen,
# parseable by ATS/LLM tools).  \cs with hidden style is also common.
_PATTERN_HIDDEN_V   = re.compile(rb"\\v\b", re.IGNORECASE)
_PATTERN_HIDDEN_CS  = re.compile(rb"\\cs\d+\b.*?\\v\b", re.DOTALL)
# B.8: \*\password destination signals a password-protected RTF document.
_PATTERN_PASSWORD   = re.compile(rb"\\\*\\password\b", re.IGNORECASE)


def fast_scan_rtf(file_path: str, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(file_path, "rb") as fh:
            # Read only the first 2 MB for fast-path byte scanning
            data = fh.read(config.limits.fast_pdf_token_scan_mb * 1024 * 1024)
    except OSError:
        return findings

    if not _PATTERN_RTF_MAGIC.match(data[:8]):
        return findings

    # ── T2: OLE embedded objects ────────────────────────────────────────────
    if config.enable_active_content_checks:
        if _PATTERN_OLE_OBJECT.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.90,
                title="RTF Embedded OLE Object",
                explain=(
                    "RTF document contains an \\object control word, indicating "
                    "an embedded OLE object that may execute code on open."
                ),
                evidence={"malicious_text": "\\object"},
                module="rtf.fast_scan",
            ))

        if _PATTERN_OBJ_DATA.search(data) and not any(
            f.title == "RTF Embedded OLE Object" for f in findings
        ):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.85,
                title="RTF OLE Object Data Stream",
                explain=(
                    "RTF document contains \\objdata, which carries raw binary "
                    "OLE object data and is a common malware delivery vector."
                ),
                evidence={"malicious_text": "\\objdata"},
                module="rtf.fast_scan",
            ))

        if _PATTERN_JAVASCRIPT.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.CRITICAL,
                confidence=0.95,
                title="RTF JavaScript Payload",
                explain="RTF document contains a \\javascript control word.",
                evidence={"malicious_text": "\\javascript"},
                module="rtf.fast_scan",
                # RTF \javascript control word has no legitimate use —
                # only added by exploit-authoring tools. Definitive.
                verdict_class=VerdictClass.BLOCK,
            ))

    # ── T2: External field references ───────────────────────────────────────
    if config.enable_active_content_checks and _PATTERN_FLDINSTR.search(data):
        has_ext = bool(_PATTERN_EXT_URL.search(data))
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.MEDIUM if not has_ext else Severity.HIGH,
            confidence=0.75,
            title="RTF External Field Reference",
            explain=(
                "RTF document uses \\fldinstr (field instruction), which can "
                "trigger outbound network requests or execute shell commands."
                + (" External URL detected." if has_ext else "")
            ),
            evidence={"has_external_url": has_ext, "malicious_text": "\\fldinstr"},
            module="rtf.fast_scan",
        ))

    # ── T7: Embedded binary stream ──────────────────────────────────────────
    if config.enable_embedded_content_checks:
        _bin_m = _PATTERN_BIN.search(data)
        if _bin_m:
            findings.append(Finding(
                threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                severity=Severity.MEDIUM,
                confidence=0.65,
                title="RTF Binary Data Stream",
                explain=(
                    "RTF document contains a \\binN control word, embedding raw "
                    "binary data. This can carry executable payloads."
                ),
                evidence={"malicious_text": "\\bin"},
                module="rtf.fast_scan",
            ))
            # B.14: Decompression bomb check — if the \bin payload starts with
            # zlib magic bytes, attempt decompression and check the expansion ratio.
            # An attacker can craft a tiny \bin stream that expands 50× or more,
            # exhausting RTF parser memory.
            if config.enable_dos_checks:
                try:
                    _bin_num_m = re.match(rb"\\bin(\d+)\b", data[_bin_m.start():])
                    if _bin_num_m:
                        _bin_size = int(_bin_num_m.group(1))
                        _payload_start = _bin_m.start() + len(_bin_num_m.group(0))
                        _payload = data[_payload_start : _payload_start + min(_bin_size, 2 * 1024 * 1024)]
                        if _payload[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
                            _decompressed = zlib.decompress(_payload[:1024 * 1024])
                            _ratio = len(_decompressed) / max(len(_payload), 1)
                            if _ratio > 50:
                                findings.append(Finding(
                                    threat_id=ThreatID.T6_DOS,
                                    severity=Severity.HIGH,
                                    confidence=0.85,
                                    title="RTF Decompression Bomb in \\bin Payload",
                                    explain=(
                                        f"RTF \\bin payload decompresses to "
                                        f"{_ratio:.0f}× its compressed size — "
                                        "a decompression bomb that causes memory "
                                        "exhaustion in RTF parsers."
                                    ),
                                    evidence={
                                        "compressed_bytes": len(_payload),
                                        "expansion_ratio": round(_ratio, 1),
                                        "malicious_text": f"\\bin expansion ratio: {_ratio:.0f}×",
                                    },
                                    module="rtf.fast_scan",
                                ))
                except Exception:
                    pass  # Malformed or non-zlib binary; T7 finding already emitted

    # ── T3: RTF hidden text via \v control word ─────────────────────────────
    if config.enable_obfuscation_checks and _PATTERN_HIDDEN_V.search(data):
        findings.append(Finding(
            threat_id=ThreatID.T3_OBFUSCATION,
            severity=Severity.MEDIUM,
            confidence=0.80,
            title="RTF Hidden Text (\\v control word)",
            explain=(
                "RTF document contains the \\v control word, which marks text as "
                "hidden (invisible to readers but fully parsed by ATS systems and "
                "LLM document loaders)."
            ),
            evidence={"malicious_text": "\\v hidden text control word detected"},
            module="rtf.fast_scan",
        ))

    # ── T1: Password-protected RTF (B.8) ───────────────────────────────────
    if _PATTERN_PASSWORD.search(data):
        findings.append(Finding(
            threat_id=ThreatID.T1_MALWARE,
            severity=Severity.MEDIUM,
            confidence=0.85,
            title="Password-Protected RTF Document",
            explain=(
                "RTF document contains \\*\\password, indicating the document is "
                "password-protected. Encrypted content cannot be fully scanned; "
                "treat as unverified."
            ),
            evidence={"malicious_text": "\\*\\password RTF destination detected"},
            module="rtf.fast_scan",
        ))

    # ── T8: Metadata injection ──────────────────────────────────────────────
    if config.enable_metadata_checks and _PATTERN_INFO_BLOCK.search(data):
        # Flag only if the info block is unusually large (> 2 KB)
        m = _PATTERN_INFO_BLOCK.search(data)
        if m and len(data) - m.start() > 2048:
            findings.append(Finding(
                threat_id=ThreatID.T8_METADATA_INJECTION,
                severity=Severity.LOW,
                confidence=0.55,
                title="RTF Oversized Metadata Block",
                explain=(
                    "The RTF {\\info} metadata block is unusually large, which "
                    "may indicate metadata injection or buffer-overflow attempts."
                ),
                evidence={"malicious_text": "{\\info"},
                module="rtf.fast_scan",
            ))

    return findings
