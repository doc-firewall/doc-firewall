from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from ...config import ScanConfig
from ...enums import Severity, ThreatID, VerdictClass
from ...report import Finding
from ..base import ParsedDocument
from .action_resolver import resolve_pdf_actions, summarize_actions
from .js_risk import benign_js_only
from .uri_classify import classify_pdf_uris

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

# H.5 (0.4.8): /URI classification (suspicious schemes, remote/executable
# file: targets, local export artifacts) lives in uri_classify.py — shared
# with the fast scan by import, not by copy.


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
        evidence: Dict[str, Any] = {"hits": hits, "bytes_scanned": max_read}
        verdict_class = VerdictClass.REVIEW
        explain = (
            "Detected PDF keys associated with actions, scripts, "
            "embedded files, or external links."
        )

        # H.2 (0.4.8): resolve what /OpenAction and /AA actually execute, so
        # the finding reports the action target (script body, URI, launch
        # command) instead of just the token name — and so that the single
        # most common benign case (/OpenAction → /GoTo "open at page N",
        # present in most exported PDFs that set an opening view) stops
        # raising MEDIUM/HIGH on zero evidence.
        hit_tokens = {h["token"] for h in hits}
        if hit_tokens & {"/OpenAction", "/AA"}:
            actions = resolve_pdf_actions(blob)
            if actions:
                evidence.update(summarize_actions(actions))
                only_triggers = hit_tokens <= {"/OpenAction", "/AA"}
                if evidence.get("all_benign") and only_triggers:
                    sev = Severity.LOW
                    verdict_class = VerdictClass.INFO
                    explain = (
                        "The document's open-action resolves to internal page "
                        "navigation only ('open at page N') — a standard "
                        "feature of exported PDFs, not active content."
                    )
                elif evidence.get("malicious_text"):
                    explain = (
                        "Detected PDF action keys; the action target was "
                        "resolved and is included in the evidence "
                        "(malicious_text)."
                    )

        # JS risk tiering: when the document's active content is benign
        # form/viewer JavaScript (incl. compressed) and there is no dangerous
        # non-JS action token, demote to INFO. Ubiquitous in benign
        # AcroForm/government PDFs; recall on dangerous JS is untouched.
        if (
            verdict_class == VerdictClass.REVIEW
            and (hit_tokens & {"/JavaScript", "/JS", "/AA", "/OpenAction"})
            and benign_js_only(blob)
        ):
            sev = Severity.LOW
            verdict_class = VerdictClass.INFO
            evidence["js_risk"] = "benign"
            explain = (
                "The document's JavaScript was resolved and uses only benign "
                "form/viewer APIs (field calculation/formatting, viewer checks) "
                "with no code-execution, network or data-exfiltration primitive, "
                "and no dangerous non-JS action is present. Recorded for audit — "
                "not a verdict driver."
            )

        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=sev,
                title="PDF contains active-content indicators",
                explain=explain,
                evidence=evidence,
                module="pdf.active_content",
                verdict_class=verdict_class,
            )
        )

    suspicious_uris, local_artifacts = classify_pdf_uris(blob)
    if suspicious_uris:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                title="PDF contains hyperlink with suspicious URL scheme",
                explain=(
                    "/URI entries reference javascript:, data:, vbscript:, "
                    "jar:, IP-literal targets, or file:// links to a remote "
                    "host or an executable. Plain http(s)/mailto/tel "
                    "hyperlinks and local file:// document paths are not "
                    "flagged."
                ),
                evidence={
                    "suspicious_uris": suspicious_uris,
                    "malicious_text": suspicious_uris[0]["target"],
                },
                module="pdf.active_content",
                confidence=0.9,
                # javascript:/data:/vbscript:/jar:/IP-literal hyperlinks and
                # remote-host/executable file:// targets have no legitimate
                # use case — definitive code-execution or data-exfil vector.
                verdict_class=VerdictClass.BLOCK,
            )
        )
    if local_artifacts:
        # H.5 (0.4.8): Office→PDF export on Windows bakes the author's
        # internal file:// links into the PDF link table. Leftover artifact,
        # not an attack vector — record for audit, never affect the verdict.
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.LOW,
                title="PDF contains local file-path links (export artifact)",
                explain=(
                    "Hyperlinks point at local file paths from the document "
                    "author's machine — a common leftover when a Word/Office "
                    "document with internal links is exported to PDF. They "
                    "cannot execute anything and do not affect the verdict."
                ),
                evidence={
                    "local_file_links": local_artifacts,
                    "malicious_text": local_artifacts[0]["target"],
                },
                module="pdf.active_content",
                confidence=0.9,
                verdict_class=VerdictClass.INFO,
            )
        )
    return findings
