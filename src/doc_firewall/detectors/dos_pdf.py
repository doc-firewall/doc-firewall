from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()


class PdfDoSDetector(Detector):
    name = "dos_pdf"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        # DEEP scan logic: Page count, etc
        findings = []
        if not config.enable_dos_checks:
            return []

        # Check parsed metadata for page count
        if doc.pdf and "docling" in doc.pdf:
            data = doc.pdf["docling"]
            if isinstance(data, dict):
                pages = data.get("pages", [])
                if isinstance(pages, list):
                    page_count = len(pages)
                    if page_count > config.limits.max_pages:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.HIGH,
                                title="PDF has excessive page count",
                                explain=(
                                    f"PDF contains {page_count} pages, which "
                                    f"exceeds the limit of {config.limits.max_pages}."
                                ),
                                evidence={
                                    "page_count": page_count,
                                    "limit": config.limits.max_pages,
                                },
                                module=self.name,
                                confidence=1.0,
                            )
                        )
        return findings

    @staticmethod
    def fast_scan(file_path: str, config: ScanConfig) -> List[Finding]:
        findings = []
        if not config.enable_dos_checks:
            return []

        limit_bytes = config.limits.fast_pdf_token_scan_mb * 1024 * 1024

        # 1. Object Density Heuristic
        # Count " obj" occurrences in the first chunk
        # try:
        with open(file_path, "rb") as f:
            data = f.read(limit_bytes)

        obj_count = data.count(b" obj")
        # If we see > 500 objects per 100KB, it's very dense.
        # Example: 2MB file, read 2MB.
        size_kb = len(data) / 1024
        if size_kb > 50:  # Ignore very small files (<50KB) to avoid noise
            density = obj_count / size_kb
            if density > 300:  # Increased from 200 to reduce FPs on obfuscated files
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="High PDF Object Density (DoS Risk)",
                        explain=(
                            f"Detected high density of PDF objects ({density:.1f} "
                            "objs/KB), which may consume excessive memory during "
                            "parsing."
                        ),
                        evidence={"density": density, "obj_count": obj_count},
                        module="dos_pdf.fast",
                        confidence=0.7,
                    )
                )

        # 2. Stream Inflation / Large Stream Check
        # /Length 12345
        try:
            # Only care if 4+ digits to save time
            large_stream_pattern = re.compile(rb"/Length\s+(\d{4,})")
            matches = large_stream_pattern.findall(data)
            max_stream_size = 0
            for m in matches:
                try:
                    s = int(m)
                    if s > max_stream_size:
                        max_stream_size = s
                except ValueError:
                    pass

            if max_stream_size > 100 * 1024 * 1024:  # 100MB
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="Massive PDF Stream Declared",
                        explain=(
                            f"PDF declares a stream of "
                            f"{max_stream_size / 1024 / 1024:.1f} MB. "
                            "This may be a decompression bomb."
                        ),
                        evidence={"max_stream_size": max_stream_size},
                        module="dos_pdf.fast",
                        confidence=0.8,
                    )
                )
        except Exception as e:
            logger.debug("Error scanning PDF for DoS: %s", e)

        # except Exception as e:
        #    pass # Fast scan should be resilient

        return findings
