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

# D.9: SVG / MathML / CSS / object-embed / HTML smuggling vectors
_PATTERN_SVG_SCRIPT    = re.compile(rb"<svg\b[^>]*>.{0,2000}?<script\b", re.IGNORECASE | re.DOTALL)
_PATTERN_SVG_ONEVENT   = re.compile(rb"<svg\b[^>]*\bon\w{2,16}\s*=", re.IGNORECASE)
_PATTERN_SVG_FOREIGN   = re.compile(rb"<svg\b[^>]*>.{0,2000}?<foreignObject\b", re.IGNORECASE | re.DOTALL)
_PATTERN_MATHML_HREF   = re.compile(rb"<math\b[^>]*>.{0,2000}?\bxlink:href\s*=", re.IGNORECASE | re.DOTALL)
_PATTERN_CSS_AT_IMPORT_JS = re.compile(rb"@import\s+url\(\s*['\"]?javascript:", re.IGNORECASE)
_PATTERN_CSS_URL_JS    = re.compile(rb"\burl\(\s*['\"]?javascript:", re.IGNORECASE)
_PATTERN_OBJECT        = re.compile(rb"<object\b[^>]*\b(?:data|src)\s*=", re.IGNORECASE)
_PATTERN_EMBED         = re.compile(rb"<embed\b[^>]*\bsrc\s*=", re.IGNORECASE)
_PATTERN_SCRIPT_TYPE_MODULE = re.compile(rb"<script\b[^>]*\btype\s*=\s*['\"]?module", re.IGNORECASE)
# HTML smuggling — large base64 atob() decode reassembled into a Blob
_PATTERN_HTML_SMUGGLE  = re.compile(
    rb"\batob\(\s*['\"][A-Za-z0-9+/=]{500,}['\"]\s*\)",
    re.IGNORECASE,
)
_PATTERN_BLOB_CTOR     = re.compile(
    rb"new\s+Blob\s*\(|URL\.createObjectURL\s*\(",
    re.IGNORECASE,
)


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

        # D.9: SVG / MathML / CSS / object / embed / module / smuggling
        if _PATTERN_SVG_SCRIPT.search(data) or _PATTERN_SVG_ONEVENT.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.90,
                title="SVG with Embedded Script / Event Handler",
                explain=(
                    "SVG element contains <script> or an inline event handler. "
                    "SVG-XSS is a documented evasion path for HTML sanitisers."
                ),
                evidence={"subtype": "svg_xss", "malicious_text": "<svg>...<script"},
                module="html.fast_scan",
            ))

        if _PATTERN_SVG_FOREIGN.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.75,
                title="SVG <foreignObject> Element",
                explain=(
                    "SVG <foreignObject> can host arbitrary HTML — used to "
                    "smuggle scripts past sanitisers that whitelist SVG."
                ),
                evidence={"subtype": "svg_foreign_object",
                          "malicious_text": "<foreignObject"},
                module="html.fast_scan",
            ))

        if _PATTERN_MATHML_HREF.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.75,
                title="MathML xlink:href",
                explain=(
                    "MathML element contains xlink:href — historic XSS surface "
                    "via xlink:href=\"javascript:...\" forms."
                ),
                evidence={"subtype": "mathml_href",
                          "malicious_text": "<math> xlink:href"},
                module="html.fast_scan",
            ))

        if _PATTERN_CSS_AT_IMPORT_JS.search(data) or _PATTERN_CSS_URL_JS.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                confidence=0.90,
                title="CSS javascript: URL",
                explain=(
                    "CSS @import or url() references a javascript: URI — "
                    "executes script via legacy CSS evaluation paths."
                ),
                evidence={"subtype": "css_javascript_uri",
                          "malicious_text": "css url(javascript:"},
                module="html.fast_scan",
            ))

        if _PATTERN_OBJECT.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title="HTML <object> Element",
                explain=(
                    "<object data=…> can load Flash/Java/PDF and execute "
                    "embedded plugin code."
                ),
                evidence={"subtype": "object_tag",
                          "malicious_text": "<object data="},
                module="html.fast_scan",
            ))

        if _PATTERN_EMBED.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title="HTML <embed> Element",
                explain=(
                    "<embed src=…> loads plugin content — historic exploit "
                    "delivery for Flash/Silverlight/PDF."
                ),
                evidence={"subtype": "embed_tag",
                          "malicious_text": "<embed src="},
                module="html.fast_scan",
            ))

        if _PATTERN_SCRIPT_TYPE_MODULE.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title="HTML ES Module Script",
                explain=(
                    "<script type=\"module\"> imports remote ESM resources "
                    "(import statements bypass naive sanitiser logic)."
                ),
                evidence={"subtype": "script_module",
                          "malicious_text": "<script type=module"},
                module="html.fast_scan",
            ))

        # HTML smuggling — large atob() decode + Blob constructor reassembly
        if _PATTERN_HTML_SMUGGLE.search(data) and _PATTERN_BLOB_CTOR.search(data):
            findings.append(Finding(
                threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                severity=Severity.HIGH,
                confidence=0.85,
                title="HTML Smuggling Indicator (atob + Blob)",
                explain=(
                    "Document contains a large base64 blob decoded via atob() "
                    "and reassembled via Blob() / URL.createObjectURL() — the "
                    "canonical HTML-smuggling delivery pattern."
                ),
                evidence={"subtype": "html_smuggling",
                          "malicious_text": "atob(...) + new Blob"},
                module="html.fast_scan",
                mitre_technique="T1027.006",
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
