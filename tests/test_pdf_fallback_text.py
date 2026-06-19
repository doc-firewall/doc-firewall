"""Real-world FP fix (0.5.0): the fallback PDF text extractor must not feed
undecoded binary stream bytes to the text detectors.

When the high-quality parser (Docling) is unavailable, `_fallback_pdf` pulls
text out of PDF ``( ... )`` literals with a regex. That regex also matches
across compressed content streams, where stray 0x28/0x29 bytes bracket large
spans of binary (FlateDecode) data — which then reached the NLP detectors and
drove a ~98% false-positive rate on a real benign-PDF corpus. `_is_textual`
filters those binary spans out (script-agnostically) while keeping real text.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.utils.docling_convert import _fallback_pdf, _is_textual


class TestIsTextual:
    def test_prose_kept_any_script(self):
        assert _is_textual("Thank you for considering my application.")
        assert _is_textual("感谢您的耐心等待")          # Chinese — no spaces
        assert _is_textual("شكرا جزيلا على وقتك")       # Arabic
        assert _is_textual("Спасибо за вашу помощь")    # Cyrillic

    def test_binary_stream_rejected(self):
        binary = "".join(chr(b) for b in (0x48, 0x16, 0x01, 0x4e, 0x06, 0x14,
                                          0x10, 0x04, 0x0c, 0x1f, 0x0e, 0x07)) * 5
        assert not _is_textual(binary)

    def test_empty_rejected(self):
        assert not _is_textual("")


class TestFallbackPdfFiltersBinary:
    def _pdf(self, tmp_path, body: bytes) -> str:
        p = tmp_path / "x.pdf"
        p.write_bytes(b"%PDF-1.5\n" + body + b"\n%%EOF\n")
        return str(p)

    def test_real_text_extracted(self, tmp_path):
        path = self._pdf(tmp_path, b"BT (Hello world this is a document) Tj ET")
        text, _ = _fallback_pdf(path)
        assert "Hello world" in text

    def test_binary_stream_not_in_text(self, tmp_path):
        # A ( ) span full of control bytes (as a compressed stream would yield)
        # must be dropped, while the adjacent real text survives.
        binary = bytes((0x16, 0x01, 0x4e, 0x06, 0x14, 0x10, 0x04, 0x0c, 0x1f)) * 8
        body = b"BT (Legitimate caption text) Tj ET\nstream\n(" + binary + b")\nendstream"
        path = self._pdf(tmp_path, body)
        text, _ = _fallback_pdf(path)
        assert "Legitimate caption text" in text
        # No C0 control characters leaked into the extracted text.
        ctrl = sum(1 for c in text if (ord(c) < 0x20 and c not in "\t\n\r"))
        assert ctrl == 0, f"binary leaked into fallback text: {ctrl} control chars"
