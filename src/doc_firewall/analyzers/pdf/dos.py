from __future__ import annotations
import os
from typing import List
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument


def detect_pdf_dos(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    size_mb = os.path.getsize(doc.file_path) / (1024 * 1024)

    # 1. File Size Check
    if size_mb > config.limits.max_mb:
        findings.append(
            Finding(
                threat_id=ThreatID.T6_DOS,
                severity=Severity.HIGH,
                title="File exceeds size limit",
                explain=f"PDF is {size_mb:.2f} MB, limit is {config.limits.max_mb} MB.",
                evidence={"size_mb": size_mb, "limit_mb": config.limits.max_mb},
                module="pdf.dos",
            )
        )

    # 2. Logic Bomb / Page Count Check
    # docling output dictionary usually contains 'pages' list
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
                                f"PDF contains {page_count} pages, which exceeds "
                                f"the limit of {config.limits.max_pages}. "
                                "This can be used for resource exhaustion."
                            ),
                            evidence={
                                "page_count": page_count,
                                "limit": config.limits.max_pages,
                            },
                            module="pdf.dos",
                        )
                    )

    return findings
