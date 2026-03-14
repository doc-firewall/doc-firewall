from __future__ import annotations
import zipfile
from typing import List

from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument


def detect_pptx_macros(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    """Detect VBA macro projects embedded in a PPTX file."""
    if doc.file_type != "pptx":
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
                            title="PPTX contains VBA macro project",
                            explain=(
                                "Macro-enabled content detected in the presentation. "
                                "Macros are a high-risk active-content vector."
                            ),
                            evidence={"artifact": name},
                            module="pptx.macros",
                        )
                    )
    except zipfile.BadZipFile:
        pass
    return findings
