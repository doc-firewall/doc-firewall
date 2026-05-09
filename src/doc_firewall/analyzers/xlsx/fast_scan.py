from __future__ import annotations
import re
import zipfile
from typing import List

from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()



STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]

# ── Hidden content patterns (H1 parity for XLSX) ──────────────────────────
# 1. Near-white cell color in xl/styles.xml: ARGB "FF" + RGB ∈ [EF]{6}
#    R,G,B ≥ 0xEE (238/255) = invisible on white sheet.
_XLSX_WHITE_COLOR_RE = re.compile(
    rb'<color\s+rgb="FF([EF]{6})"', re.IGNORECASE
)
# 2. Hide-all custom number format ";;;" — renders no value for any cell type
_XLSX_HIDE_ALL_RE = re.compile(rb'formatCode=";;;"', re.IGNORECASE)
# 3. Hidden rows / columns in worksheet XML
_XLSX_HIDDEN_ROW_RE = re.compile(rb'<row\b[^>]+\bhidden="1"')
_XLSX_HIDDEN_COL_RE = re.compile(rb'<col\b[^>]+\bhidden="1"')


def _check_hidden_xlsx_styles(content: bytes) -> list[tuple[str, str]]:
    """Detect hidden-text techniques in xl/styles.xml bytes."""
    hits: list[tuple[str, str]] = []
    m = _XLSX_WHITE_COLOR_RE.search(content)
    if m:
        hits.append(("white_color", f"near-white cell color: #{m.group(1).decode()}"))
    if _XLSX_HIDE_ALL_RE.search(content):
        hits.append(("hide_all_format", 'hide-all number format ";;;" found'))
    return hits


def fast_scan_xlsx(file_path: str, config: ScanConfig) -> List[Finding]:
    """Fast structural scan of an XLSX (ZIP-based) file."""
    findings: List[Finding] = []

    if not zipfile.is_zipfile(file_path):
        return findings

    with zipfile.ZipFile(file_path, "r") as zf:
        infolist = zf.infolist()
        part_count = len(infolist)
        total_uncompressed = sum(z.file_size for z in infolist)
        total_compressed = sum(z.compress_size for z in infolist)
        overall_ratio = (
            total_uncompressed / total_compressed if total_compressed > 0 else 0
        )

        # 1. DoS / structure checks
        if part_count > config.limits.max_xlsx_parts:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many XLSX parts",
                    explain=(
                        f"File contains {part_count} parts "
                        f"(limit {config.limits.max_xlsx_parts})."
                    ),
                    evidence={
                        "part_count": part_count,
                        "limit": config.limits.max_xlsx_parts,
                    },
                    module="fast_scan.xlsx.structure",
                )
            )

        total_mb = total_uncompressed / (1024 * 1024)
        if total_mb > config.limits.max_xlsx_total_uncompressed_mb:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="XLSX total uncompressed size too large",
                    explain=(
                        f"Uncompressed size {total_mb:.2f} MB exceeds limit "
                        f"{config.limits.max_xlsx_total_uncompressed_mb} MB."
                    ),
                    evidence={"size_mb": total_mb},
                    module="fast_scan.xlsx.structure",
                )
            )

        sheet_count = sum(
            1
            for z in infolist
            if z.filename.startswith("xl/worksheets/sheet")
            and z.filename.endswith(".xml")
        )
        if sheet_count > config.limits.max_pages:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.MEDIUM,
                    title="Excessive worksheet count",
                    explain=(
                        f"Workbook contains {sheet_count} sheets "
                        f"(limit {config.limits.max_pages})."
                    ),
                    evidence={"sheet_count": sheet_count},
                    module="fast_scan.xlsx.structure",
                )
            )

        suspicious_parts = 0

        # 2. Per-part checks
        for z in infolist:
            # Large individual part
            if z.file_size > config.limits.max_xlsx_single_part_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Large individual XLSX part",
                        explain=(
                            f"Part {z.filename} is {z.file_size / 1024 / 1024:.2f} MB."
                        ),
                        evidence={
                            "filename": z.filename,
                            "size_mb": z.file_size / 1024 / 1024,
                        },
                        module="fast_scan.xlsx.structure",
                    )
                )

            # Compression ratio (zip bomb heuristic)
            ratio = z.file_size / z.compress_size if z.compress_size > 0 else 0
            if (
                ratio > getattr(config.limits, "max_docx_overall_expansion_ratio", 200)
                and z.file_size > 1024 * 1024
            ):
                suspicious_parts += 1

            # VBA macros (xlsm / xls files with macro support)
            if z.filename.endswith("vbaProject.bin") or "macrosheets" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="XLSX contains VBA macro project",
                        explain=(
                            f"Found '{z.filename}' indicating macro-enabled content. "
                            "Macros in spreadsheets are a critical active-content risk."
                        ),
                        evidence={"filename": z.filename},
                        module="fast_scan.xlsx.macros",
                    )
                )

            # Embedded objects
            if z.filename.startswith("xl/embeddings/"):
                if z.file_size > config.limits.min_embedded_object_size_bytes:
                    evidence = {"filename": z.filename, "size": z.file_size}
                    severity = Severity.MEDIUM
                    title = "XLSX embedded object found"
                    explain = f"Found embedded object '{z.filename}'."
                    try:
                        with zf.open(z.filename) as emf:
                            header = emf.read(4096)
                            if header.startswith(b"\xD0\xCF\x11\xE0"):
                                severity = Severity.HIGH
                                title = "Malicious OLE Payload Signature"
                                explain += " Contains OLE binary header."
                            elif header.startswith(b"MZ"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains DOS MZ header."
                            elif header.startswith(b"\x7FELF"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains ELF binary header."
                    except Exception:
                        pass

                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=severity,
                            title=title,
                            explain=explain,
                            evidence=evidence,
                            module="fast_scan.xlsx.ole",
                        )
                    )

            # External relationships
            if z.filename.endswith(".rels"):
                try:
                    with zf.open(z) as f:
                        rel_content = f.read(512 * 1024)
                        if b'TargetMode="External"' in rel_content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                    severity=Severity.MEDIUM,
                                    title="XLSX external relationship found",
                                    explain=(
                                        f"Found 'TargetMode=\"External\"' in "
                                        f"{z.filename}, indicating external content."
                                    ),
                                    evidence={"filename": z.filename},
                                    module="fast_scan.xlsx.rels",
                                )
                            )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # Hidden content in styles (white-color cells, hide-all number format)
            if z.filename == "xl/styles.xml":
                try:
                    with zf.open(z) as f:
                        styles_content = f.read(512 * 1024)
                    for technique, detail in _check_hidden_xlsx_styles(styles_content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title=f"XLSX Hidden Text Technique ({technique})",
                                explain=(
                                    f"Detected {detail} in xl/styles.xml. "
                                    "Cell content styled to be invisible to human "
                                    "readers but present in the data stream."
                                ),
                                evidence={"technique": technique, "detail": detail},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading xl/styles.xml: %s", e)

            # Formula / DDE injection — scan worksheet XML for =,+,-,@ starts
            # Also keyword scan in sheet content
            if z.filename.startswith("xl/worksheets/sheet") and z.filename.endswith(
                ".xml"
            ):
                try:
                    with zf.open(z) as f:
                        content = f.read(1024 * 1024)  # 1 MB cap
                    content_lower = content.lower()

                    # DDE injection heuristic: =DDE( or =CMD patterns
                    if b"=dde(" in content_lower or b"=cmd|" in content_lower:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T9_ATS_MANIPULATION,
                                severity=Severity.HIGH,
                                title="Potential DDE injection in XLSX",
                                explain=(
                                    f"Found DDE formula pattern in {z.filename}. "
                                    "This can be used for ATS manipulation."
                                ),
                                evidence={"part": z.filename},
                                module="fast_scan.xlsx.dde",
                            )
                        )
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                severity=Severity.HIGH,
                                title="Potential DDE injection in XLSX",
                                explain=(
                                    f"Found DDE formula pattern in {z.filename}. "
                                    "DDE formulas can execute arbitrary commands."
                                ),
                                evidence={"filename": z.filename},
                                module="fast_scan.xlsx.dde",
                            )
                        )
                    for kw in config.prompt_injection_keywords_bytes:
                        if kw in content_lower:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T4_PROMPT_INJECTION,
                                    severity=Severity.MEDIUM,
                                    title="Potential injection keyword (XLSX fast scan)",
                                    explain=(
                                        f"Found keyword '{kw.decode('ascii')}' "
                                        f"in {z.filename}."
                                    ),
                                    evidence={
                                        "keyword": kw.decode("ascii"),
                                        "part": z.filename,
                                    },
                                    module="fast_scan.xlsx.keywords",
                                )
                            )

                    for char_bytes, name in STEALTH_CHARS:
                        if char_bytes in content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T3_OBFUSCATION,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious hidden character ({name}) in XLSX",
                                    explain=(
                                        f"Found {name} in {z.filename}, "
                                        "possible stealth injection."
                                    ),
                                    evidence={"char": name, "part": z.filename},
                                    module="fast_scan.xlsx.stealth",
                                )
                            )

                    # H1 parity: hidden rows / columns
                    if _XLSX_HIDDEN_ROW_RE.search(content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title="XLSX Hidden Rows Detected",
                                explain=(
                                    f"Worksheet {z.filename} contains rows with "
                                    'hidden="1" — content invisible to the user '
                                    "but readable by parsers and ATS systems."
                                ),
                                evidence={"part": z.filename, "technique": "hidden_row"},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                    if _XLSX_HIDDEN_COL_RE.search(content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title="XLSX Hidden Columns Detected",
                                explain=(
                                    f"Worksheet {z.filename} contains columns with "
                                    'hidden="1" — content invisible to the user '
                                    "but readable by parsers and ATS systems."
                                ),
                                evidence={"part": z.filename, "technique": "hidden_col"},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

        # Zip bomb aggregate check
        if suspicious_parts >= 2 or (
            overall_ratio > config.limits.max_docx_overall_expansion_ratio
            and total_mb > 10
        ):
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="XLSX suspicious compression ratio",
                    explain=(
                        "High compression ratio detected, characteristic of zip "
                        "bombs or generated obfuscation."
                    ),
                    evidence={
                        "overall_ratio": round(overall_ratio, 2),
                        "suspicious_parts": suspicious_parts,
                    },
                    module="fast_scan.xlsx.structure",
                )
            )

    return findings
