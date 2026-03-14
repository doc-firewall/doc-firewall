from __future__ import annotations
import zipfile
from typing import List

from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument


def detect_xlsx_macros(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    """Detect VBA macro projects embedded in an XLSX / XLSM file."""
    if doc.file_type != "xlsx":
        return []
    findings: List[Finding] = []
    try:
        with zipfile.ZipFile(doc.file_path, "r") as zf:
            names = set(zf.namelist())
            for name in names:
                if name.endswith("vbaProject.bin") or "macrosheets" in name:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T2_ACTIVE_CONTENT,
                            severity=Severity.HIGH,
                            title="XLSX contains VBA macro project",
                            explain=(
                                "Macro-enabled content detected in the workbook. "
                                "Macros are a critical active-content attack vector."
                            ),
                            evidence={"artifact": name},
                            module="xlsx.macros",
                        )
                    )
    except zipfile.BadZipFile:
        pass
    return findings
