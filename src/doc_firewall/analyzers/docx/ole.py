from __future__ import annotations
import zipfile
from typing import List
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument


def detect_docx_ole_objects(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    if doc.file_type != "docx":
        return []
    findings = []
    embedded = []
    try:
        with zipfile.ZipFile(doc.file_path, "r") as z:
            for n in z.namelist():
                lower = n.lower()
                if lower.startswith("word/embeddings/") or lower.startswith(
                    "word/oleobject"
                ):
                    info = z.getinfo(n)
                    embedded.append(
                        {
                            "path": n,
                            "compressed_size": info.compress_size,
                            "uncompressed_size": info.file_size,
                        }
                    )
    except zipfile.BadZipFile:
        return findings

    if embedded:
        total_uncompressed = sum(x["uncompressed_size"] for x in embedded)
        if len(embedded) > config.limits.max_embedded_files or total_uncompressed > (
            config.limits.max_mb * 1024 * 1024
        ):
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=sev,
                title="DOCX contains embedded objects (OLE/Package)",
                explain=(
                    "Embedded objects can carry active content or payloads. "
                    "Review or sanitize before downstream processing."
                ),
                evidence={
                    "embedded_objects": embedded,
                    "count": len(embedded),
                    "total_uncompressed_bytes": total_uncompressed,
                },
                module="docx.ole",
            )
        )
    return findings
