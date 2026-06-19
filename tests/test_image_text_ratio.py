"""W4 (0.5.0) — image-based-injection advisory tests.

An image-heavy / low-text document (a screenshot-of-text "résumé") is flagged
for OCR review when OCR is off; a normal text document is not; and the
advisory is suppressed when OCR is enabled.
"""
from __future__ import annotations

import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.image_text_ratio import ImageTextRatioDetector
from doc_firewall.enums import ThreatID, Verdict
from doc_firewall.scanner import Scanner

_TINY_PNG = (  # 1x1 PNG
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _run(doc: ParsedDocument, **cfg):
    config = ScanConfig(profile="balanced")
    for k, v in cfg.items():
        setattr(config, k, v)
    return ImageTextRatioDetector().run(doc, config)


def _image_only_docx(tmp_path, n_images=2, visible_text="") -> str:
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    body = f"<w:p><w:r><w:t>{visible_text}</w:t></w:r></w:p>" if visible_text else "<w:p/>"
    path = str(tmp_path / "img.docx")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/></Types>',
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        zf.writestr(
            "word/document.xml",
            f'<?xml version="1.0"?><w:document {ns}><w:body>{body}</w:body></w:document>',
        )
        for i in range(n_images):
            zf.writestr(f"word/media/image{i}.png", _TINY_PNG)
    return path


class TestDetectorUnit:
    def test_image_heavy_low_text_flagged(self, tmp_path):
        path = _image_only_docx(tmp_path, n_images=3)
        doc = ParsedDocument(file_path=path, file_type="docx", text="   ", metadata={})
        out = _run(doc)
        assert out
        assert out[0].threat_id == ThreatID.T3_OBFUSCATION
        assert out[0].evidence["subtype"] == "uninspected_images"
        assert out[0].evidence["image_count"] == 3
        assert out[0].evidence["debug_steps"]

    def test_text_rich_not_flagged(self, tmp_path):
        path = _image_only_docx(tmp_path, n_images=2)
        doc = ParsedDocument(
            file_path=path, file_type="docx",
            text="A" * 500, metadata={},  # plenty of extractable text
        )
        assert not _run(doc)

    def test_no_images_not_flagged(self, tmp_path):
        path = _image_only_docx(tmp_path, n_images=0)
        doc = ParsedDocument(file_path=path, file_type="docx", text="", metadata={})
        assert not _run(doc)

    def test_suppressed_when_ocr_enabled(self, tmp_path):
        path = _image_only_docx(tmp_path, n_images=3)
        doc = ParsedDocument(file_path=path, file_type="docx", text="", metadata={})
        assert not _run(doc, enable_ocr_injection_scan=True)

    def test_disabled(self, tmp_path):
        path = _image_only_docx(tmp_path, n_images=3)
        doc = ParsedDocument(file_path=path, file_type="docx", text="", metadata={})
        assert not _run(doc, enable_image_text_ratio=False)


def _pdf_with_images(n_images: int, text: str = "") -> bytes:
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    ]
    for i in range(n_images):
        objs.append(
            f"{4+i} 0 obj\n<< /Type /XObject /Subtype /Image /Width 100 "
            f"/Height 100 >>\nstream\n".encode() + b"\xff" * 20 + b"\nendstream\nendobj\n"
        )
    body = b"".join(objs)
    return b"%PDF-1.5\n" + body + text.encode() + b"\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


@pytest.mark.adversarial
class TestEndToEnd:
    def test_image_only_pdf_flagged(self, tmp_path):
        path = str(tmp_path / "scan.pdf")
        with open(path, "wb") as f:
            f.write(_pdf_with_images(2))
        r = Scanner(ScanConfig(profile="balanced")).scan(path)
        assert any(
            (f.evidence or {}).get("subtype") == "uninspected_images"
            for f in r.findings
        ), [f.title for f in r.findings]
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
