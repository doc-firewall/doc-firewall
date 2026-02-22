from __future__ import annotations
import zipfile
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()


class DocxDoSDetector(Detector):
    name = "dos_docx"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        # DEEP scan logic if any
        return []

    @staticmethod
    def fast_scan(file_path: str, config: ScanConfig) -> List[Finding]:
        findings = []
        if not config.enable_dos_checks:
            return []

        if not zipfile.is_zipfile(file_path):
            return []

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                infolist = zf.infolist()

                part_count = len(infolist)
                total_uncompressed = sum(z.file_size for z in infolist)
                total_compressed = sum(z.compress_size for z in infolist)

                # Check 1: Part Count
                if part_count > config.limits.max_docx_parts:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T6_DOS,
                            severity=Severity.HIGH,
                            title="Too many DOCX parts (Zip Bomb)",
                            explain=(
                                f"File contains {part_count} parts "
                                f"(limit {config.limits.max_docx_parts})."
                            ),
                            evidence={
                                "part_count": part_count,
                                "limit": config.limits.max_docx_parts,
                            },
                            module="dos_docx.fast",
                            confidence=0.9,
                        )
                    )

                # Check 2: Total Uncompressed Size
                total_mb = total_uncompressed / (1024 * 1024)
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
                            evidence={"size_mb": total_mb},
                            module="dos_docx.fast",
                            confidence=0.9,
                        )
                    )

                # Check 3: Compression Ratio
                if total_compressed > 0:
                    overall_ratio = total_uncompressed / total_compressed
                    if overall_ratio > config.limits.max_docx_overall_expansion_ratio:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.HIGH,
                                title="High Compression Ratio (Zip Bomb)",
                                explain=(
                                    f"Compression ratio {overall_ratio:.1f}:1 exceeds "
                                    f"limit "
                                    f"{config.limits.max_docx_overall_expansion_ratio}:1."
                                ),
                                evidence={"ratio": overall_ratio},
                                module="dos_docx.fast",
                                confidence=0.8,
                            )
                        )

                # Check 4: Large Individual Files
                for z in infolist:
                    if (
                        z.file_size
                        > config.limits.max_docx_single_part_mb * 1024 * 1024
                    ):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.MEDIUM,
                                title="Large individual XML part",
                                explain=(
                                    f"Part {z.filename} is "
                                    f"{z.file_size / 1024 / 1024:.2f} MB."
                                ),
                                evidence={
                                    "filename": z.filename,
                                    "size_mb": z.file_size / 1024 / 1024,
                                },
                                module="dos_docx.fast",
                                confidence=0.7,
                            )
                        )

                # Check 5: Nested Archive (Zip inside Zip)
                for z in infolist:
                    if z.filename.lower().endswith(
                        (".zip", ".docx", ".xlsx", ".pptx", ".jar")
                    ):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.MEDIUM,
                                title="Nested Archive Detected",
                                explain=(
                                    f"File {z.filename} appears to be a nested "
                                    "archive, which is unusual and a potential "
                                    "evasion/DoS vector."
                                ),
                                evidence={"filename": z.filename},
                                module="dos_docx.fast",
                                confidence=0.8,
                            )
                        )
        except Exception as e:
            logger.debug("Error scanning DOCX for DoS: %s", e)

        return findings
