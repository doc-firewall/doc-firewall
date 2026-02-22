from __future__ import annotations
from typing import List, Dict, Any
import os
import re
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument

SUSPICIOUS_TOKENS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Filespec",
    b"/URI",
    b"/AcroForm",
]


def detect_pdf_active_content(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    if doc.file_type != "pdf":
        return []
    findings: List[Finding] = []
    max_read = min(
        os.path.getsize(doc.file_path),
        config.limits.max_pdf_bytes_scan_mb * 1024 * 1024,
    )
    try:
        with open(doc.file_path, "rb") as f:
            blob = f.read(max_read)
    except Exception:
        return findings

    hits: List[Dict[str, Any]] = []
    delims_pattern = b"[\x00\t\n\f\r ()<>\\[\\]{}/%]"

    for tok in SUSPICIOUS_TOKENS:
        if tok in blob:
            pattern = re.escape(tok) + delims_pattern
            c = len(re.findall(pattern, blob))
            if c:
                hits.append({"token": tok.decode("latin-1"), "count": c})
    if hits:
        high_risk = {"/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/Filespec"}
        sev = (
            Severity.HIGH
            if any(h["token"] in high_risk for h in hits)
            else Severity.MEDIUM
        )
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=sev,
                title="PDF contains active-content indicators",
                explain=(
                    "Detected PDF keys associated with actions, scripts, "
                    "embedded files, or external links."
                ),
                evidence={"hits": hits, "bytes_scanned": max_read},
                module="pdf.active_content",
            )
        )
    return findings
