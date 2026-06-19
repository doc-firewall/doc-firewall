"""Regression: the deep XLSX parser must bound decompression per part (0.5.0).

Every XML part is read through `_safe_parse`, which reads at most
`_MAX_PARSE_BYTES` decompressed bytes. A member that under-declares its size
(a decompression bomb) is therefore skipped, not expanded into a giant DOM —
so a malicious workbook cannot exhaust memory during the deep parse.
"""
from __future__ import annotations

import io
import os
import resource
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.xlsx.parser import _MAX_PARSE_BYTES, parse_xlsx
from doc_firewall.config import ScanConfig


def _rss_gb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / 1e9 if sys.platform == "darwin" else peak / 1e6


def _xlsx_with_oversized_sheet(uncompressed_mb: int = 40) -> str:
    rows = (b"<row><c><v>1</v></c></row>") * ((uncompressed_mb * 1024 * 1024) // 26)
    big = b'<worksheet xmlns="http://x"><sheetData>' + rows + b"</sheetData></worksheet>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("xl/worksheets/sheet1.xml", big)
    path = tempfile.mktemp(suffix=".xlsx")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


class TestXlsxParseBounds:
    def test_oversized_member_is_skipped_not_expanded(self):
        path = _xlsx_with_oversized_sheet(40)  # ~40 MB uncompressed, ~KB on disk
        try:
            before = _rss_gb()
            t0 = time.time()
            doc = parse_xlsx(path, ScanConfig())
            elapsed = time.time() - t0
            grew = _rss_gb() - before
        finally:
            os.unlink(path)

        assert elapsed < 10, f"parse took {elapsed:.1f}s — not bounded"
        assert grew < 0.5, f"RSS grew {grew:.2f} GB — member was expanded"
        # The oversized sheet is skipped, so no cell text is extracted.
        assert len(doc.text) < 1000

    def test_cap_is_sane(self):
        assert 1 * 1024 * 1024 <= _MAX_PARSE_BYTES <= 64 * 1024 * 1024


def _pptx_with_oversized_slide(uncompressed_mb: int = 40) -> str:
    big = (
        b'<p:sld xmlns:p="http://x"><p:cSld>'
        + (b"<a:t>x</a:t>") * ((uncompressed_mb * 1024 * 1024) // 11)
        + b"</p:cSld></p:sld>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("ppt/slides/slide1.xml", big)
    path = tempfile.mktemp(suffix=".pptx")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


def _odf_with_oversized_content(uncompressed_mb: int = 40) -> str:
    big = b"<o>" + (b"<x>t</x>") * ((uncompressed_mb * 1024 * 1024) // 8) + b"</o>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", big)
    path = tempfile.mktemp(suffix=".odt")
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    return path


class TestPptxParseBounds:
    def test_oversized_slide_is_skipped(self):
        from doc_firewall.analyzers.pptx.parser import parse_pptx

        path = _pptx_with_oversized_slide(40)
        try:
            before = _rss_gb()
            t0 = time.time()
            doc = parse_pptx(path, ScanConfig())
            elapsed = time.time() - t0
            grew = _rss_gb() - before
        finally:
            os.unlink(path)
        assert elapsed < 10 and grew < 0.5
        assert len(doc.text) < 1000


class TestOdfParseBounds:
    def test_oversized_content_is_truncated_not_expanded(self):
        from doc_firewall.analyzers.odf.parser import parse_odf

        path = _odf_with_oversized_content(40)  # ~40 MB content.xml, ~KB on disk
        try:
            before = _rss_gb()
            t0 = time.time()
            doc = parse_odf(path, ScanConfig())
            elapsed = time.time() - t0
            grew = _rss_gb() - before
        finally:
            os.unlink(path)
        # Bounded decompression: at most ~4 MB is read, not the full 40 MB.
        assert elapsed < 10 and grew < 0.5
        assert len(doc.text) < 5 * 1024 * 1024
