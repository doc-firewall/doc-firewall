from __future__ import annotations
import zipfile
from typing import List
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument


def detect_docx_macros(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    if doc.file_type != "docx":
        return []
    findings = []
    try:
        with zipfile.ZipFile(doc.file_path, "r") as z:
            names = set(z.namelist())
            if "word/vbaProject.bin" in names or "vbaProject.bin" in names:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="DOCX contains VBA macro project (vbaProject.bin)",
                        explain=(
                            "Macro-enabled content detected. "
                            "Macros are a high-risk active-content vector."
                        ),
                        evidence={"artifact": "word/vbaProject.bin"},
                        module="docx.macros",
                    )
                )
    except zipfile.BadZipFile:
        return findings
    return findings
