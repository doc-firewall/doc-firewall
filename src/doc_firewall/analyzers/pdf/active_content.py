from __future__ import annotations
from typing import List, Dict, Any
import os
import re
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument

# Tokens that always indicate active behaviour in a PDF. /URI and /AcroForm
# are intentionally NOT in this list — a /URI is just a hyperlink (resumes
# legitimately contain mailto:/https://linkedin.com/... links), and forms by
# themselves are not malicious. /URI is checked separately below and only
# flagged when the target uses a suspicious scheme.
SUSPICIOUS_TOKENS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Filespec",
]

# URL schemes that should never appear in a benign PDF hyperlink.
_SUSPICIOUS_URI_SCHEMES = re.compile(
    rb"^(?:javascript|data|vbscript|file|jar):", re.IGNORECASE
)
# IP-literal hosts in http(s) URLs — also unusual for benign documents.
_IP_LITERAL_HOST = re.compile(
    rb"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE
)
# Match a /URI ( ... ) entry. Cap inner capture so a malformed PDF can't
# blow up the regex on a giant span.
_URI_ENTRY_RE = re.compile(rb"/URI\s*\(([^)\\]{1,2000})\)")


def _scan_suspicious_uris(blob: bytes) -> List[Dict[str, Any]]:
    """Return a list of {scheme, target} for any /URI entries whose target
    looks malicious. Plain http(s)/mailto/tel hyperlinks return nothing."""
    out: List[Dict[str, Any]] = []
    for m in _URI_ENTRY_RE.finditer(blob):
        target = m.group(1).strip()
        if _SUSPICIOUS_URI_SCHEMES.match(target) or _IP_LITERAL_HOST.match(target):
            try:
                decoded = target.decode("latin-1", errors="replace")[:200]
            except Exception:
                decoded = "<unprintable>"
            out.append({"target": decoded})
            if len(out) >= 20:
                break  # cap evidence size
    return out


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

    suspicious_uris = _scan_suspicious_uris(blob)
    if suspicious_uris:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                title="PDF contains hyperlink with suspicious URL scheme",
                explain=(
                    "/URI entries reference javascript:, data:, file:, "
                    "vbscript:, jar:, or IP-literal targets. Plain http(s)/"
                    "mailto/tel hyperlinks are not flagged."
                ),
                evidence={
                    "suspicious_uris": suspicious_uris,
                    "malicious_text": suspicious_uris[0]["target"],
                },
                module="pdf.active_content",
                confidence=0.9,
            )
        )
    return findings
