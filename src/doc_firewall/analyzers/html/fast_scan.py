"""
html/fast_scan.py — Byte-level fast scanner for HTML documents.

Detects high-confidence indicators before full parsing:
  T2: <script> blocks, inline event handlers (on*=), <iframe>, meta-refresh,
      data: URIs, form actions pointing to external URLs
  T3: CSS-based hidden text (visibility:hidden, display:none, font-size:0,
      color:white / color:#fff)
  T9: Hidden keyword stuffing via CSS hidden text
  T7: data: URIs carrying base64 blobs (potential embedded payloads)
"""
from __future__ import annotations

import re
from typing import List

from ...report import Finding
from ...config import ScanConfig
from ...enums import ThreatID, Severity


_PATTERN_SCRIPT_TAG    = re.compile(rb"<script[\s>]", re.IGNORECASE)
_PATTERN_INLINE_EVENT  = re.compile(rb"\bon\w{2,16}\s*=", re.IGNORECASE)
_PATTERN_IFRAME        = re.compile(rb"<iframe[\s>]", re.IGNORECASE)
_PATTERN_META_REFRESH  = re.compile(rb"<meta[^>]+http-equiv\s*=\s*['\"]?refresh", re.IGNORECASE)
_PATTERN_DATA_URI      = re.compile(rb"data:[^;,\s]{1,50};base64,", re.IGNORECASE)
_PATTERN_EXT_FORM      = re.compile(rb"<form[^>]+action\s*=\s*['\"]https?://", re.IGNORECASE)
# CSS hidden text patterns
_PATTERN_VISIBILITY    = re.compile(rb"visibility\s*:\s*hidden", re.IGNORECASE)
_PATTERN_DISPLAY_NONE  = re.compile(rb"display\s*:\s*none", re.IGNORECASE)
_PATTERN_FONT_SIZE_0   = re.compile(rb"font-size\s*:\s*0", re.IGNORECASE)
_PATTERN_WHITE_COLOR   = re.compile(rb"color\s*:\s*(white|#fff(?:fff)?)\b", re.IGNORECASE)
_PATTERN_OPACITY_0     = re.compile(rb"opacity\s*:\s*0\b", re.IGNORECASE)


def fast_scan_html(file_path: str, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(file_path, "rb") as fh:
            data = fh.read(config.limits.fast_pdf_token_scan_mb * 1024 * 1024)
    except OSError:
        return findings

    # Sanity check — must look like HTML
    if not re.search(rb"<html[\s>]|<!doctype\s+html", data[:512], re.IGNORECASE):
        # Still try if extension was .html but no explicit tag (fragment)
        if b"<" not in data[:512]:
            return findings

    # ── T2: Active content ──────────────────────────────────────────────────
    if config.enable_active_content_checks:
        if _PATTERN_SCRIPT_TAG.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.90,
                title="HTML Script Block",
                explain=(
                    "HTML document contains a <script> tag. JavaScript execution "
                    "can manipulate LLM context or exfiltrate data."
                ),
                evidence={"malicious_text": "<script>"},
                module="html.fast_scan",
            ))

        if _PATTERN_INLINE_EVENT.search(data):
            m = _PATTERN_INLINE_EVENT.search(data)
            snippet = m.group(0).decode("latin-1", errors="replace") if m else "on*="
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.85,
                title="HTML Inline Event Handler",
                explain=(
                    f"HTML document contains an inline JavaScript event handler "
                    f"('{snippet}'). These execute JavaScript on user interaction."
                ),
                evidence={"malicious_text": snippet[:250]},
                module="html.fast_scan",
            ))

        if _PATTERN_IFRAME.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.75,
                title="HTML Iframe Element",
                explain=(
                    "<iframe> can embed external content or be used for "
                    "clickjacking and covert resource loading."
                ),
                evidence={"malicious_text": "<iframe"},
                module="html.fast_scan",
            ))

        if _PATTERN_META_REFRESH.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.80,
                title="HTML Meta-Refresh Redirect",
                explain=(
                    "HTML document uses a meta http-equiv='refresh' tag, which "
                    "auto-redirects the browser to an attacker-controlled URL."
                ),
                evidence={"malicious_text": "meta http-equiv=refresh"},
                module="html.fast_scan",
            ))

        if _PATTERN_EXT_FORM.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title="HTML Form with External Action",
                explain=(
                    "HTML <form> submits to an external URL, which may be used "
                    "for phishing or data exfiltration."
                ),
                evidence={"malicious_text": "<form action=https://..."},
                module="html.fast_scan",
            ))

    # ── T7: data: URI with base64 blob ──────────────────────────────────────
    if config.enable_embedded_content_checks and _PATTERN_DATA_URI.search(data):
        m = _PATTERN_DATA_URI.search(data)
        snippet = m.group(0).decode("latin-1", errors="replace")[:80] if m else "data:..;base64,"
        findings.append(Finding(
            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
            severity=Severity.MEDIUM,
            confidence=0.65,
            title="HTML Inline Data URI (base64)",
            explain=(
                "HTML document embeds a base64-encoded data: URI. These can "
                "carry executable content (scripts, images, binaries)."
            ),
            evidence={"malicious_text": snippet},
            module="html.fast_scan",
        ))

    # ── T3 / T9: CSS hidden text ────────────────────────────────────────────
    if config.enable_hidden_text or config.enable_ats_manipulation_checks:
        hidden_patterns = [
            (_PATTERN_VISIBILITY, "visibility:hidden"),
            (_PATTERN_DISPLAY_NONE, "display:none"),
            (_PATTERN_FONT_SIZE_0, "font-size:0"),
            (_PATTERN_WHITE_COLOR, "color:white"),
            (_PATTERN_OPACITY_0, "opacity:0"),
        ]
        matched = [label for pat, label in hidden_patterns if pat.search(data)]
        if matched:
            findings.append(Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title="HTML CSS Hidden Text",
                explain=(
                    f"HTML document hides text with CSS properties: "
                    f"{', '.join(matched)}. This is used for invisible keyword "
                    f"stuffing or hidden prompt injection."
                ),
                evidence={"css_properties": matched,
                          "malicious_text": ", ".join(matched)},
                module="html.fast_scan",
            ))

    return findings
