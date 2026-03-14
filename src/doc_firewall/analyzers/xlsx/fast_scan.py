from __future__ import annotations
import zipfile
from typing import List

from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


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
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.MEDIUM,
                            title="XLSX embedded object found",
                            explain=f"Found embedded object '{z.filename}'.",
                            evidence={"filename": z.filename, "size": z.file_size},
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
