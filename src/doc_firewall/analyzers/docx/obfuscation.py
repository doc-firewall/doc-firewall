from __future__ import annotations
from typing import List
from ...report import Finding
from ..base import ParsedDocument
from ...config import ScanConfig


def detect_docx_obfuscation(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    # Logic moved to fast_scan_docx for earlier detection and lower latency
    return []
