"""W7 (0.5.0) — content-hash result cache tests."""
from __future__ import annotations

import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.scanner import Scanner


def _docx(tmp_path, name, text="Quarterly results were strong this period.") -> str:
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/></Types>',
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
            f'<?xml version="1.0"?><w:document {ns}><w:body>'
            f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )
    path = str(tmp_path / name)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


class TestResultCache:
    def test_disabled_by_default(self):
        assert Scanner(ScanConfig(profile="balanced"))._result_cache is None

    def test_identical_content_hits_cache(self, tmp_path):
        cfg = ScanConfig(profile="balanced")
        cfg.enable_result_cache = True
        scanner = Scanner(cfg)

        a = _docx(tmp_path, "a.docx")
        # Byte-identical copy at a different path → same hash → cache hit.
        b = str(tmp_path / "b.docx")
        with open(a, "rb") as fa, open(b, "wb") as fb:
            fb.write(fa.read())

        r1 = scanner.scan(a)
        assert len(scanner._result_cache) == 1
        r2 = scanner.scan(b)
        assert r2.verdict == r1.verdict
        assert r2.sha256 == r1.sha256
        # The returned report reflects the requested path, not the cached one.
        assert r2.file_path == b
        # Still one entry (same content hash).
        assert len(scanner._result_cache) == 1

    def test_different_content_misses(self, tmp_path):
        cfg = ScanConfig(profile="balanced")
        cfg.enable_result_cache = True
        scanner = Scanner(cfg)
        scanner.scan(_docx(tmp_path, "x.docx", "First document."))
        scanner.scan(_docx(tmp_path, "y.docx", "A completely different document."))
        assert len(scanner._result_cache) == 2

    def test_lru_eviction(self, tmp_path):
        cfg = ScanConfig(profile="balanced")
        cfg.enable_result_cache = True
        cfg.result_cache_size = 2
        scanner = Scanner(cfg)
        for i in range(4):
            scanner.scan(_docx(tmp_path, f"d{i}.docx", f"Document number {i} content."))
        assert len(scanner._result_cache) == 2
