"""File-type masquerade detection (0.5.0).

A file whose extension claims an Office document but whose bytes are a
different format (a legacy OLE binary renamed .docx, or a hollow OOXML
package) is a classic filter-evasion. Real documents never do this — it was
the dominant reason malicious .docx (legacy macro .doc masquerading as .docx)
were missed (~5% recall). The benign binary-workbook (.xlsb) case is excluded.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.enums import ThreatID, VerdictClass
from doc_firewall.scanner import Scanner, _format_masquerade_finding

_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 512  # CFB / OLE2 header


class TestMasqueradeLogic:
    def test_ooxml_ext_with_ole_content_flags(self):
        f = _format_masquerade_finding("docx", "ole")
        assert f is not None
        assert f.threat_id == ThreatID.T3_OBFUSCATION
        assert f.evidence["claimed_type"] == "docx"
        assert f.evidence["actual_type"] == "ole"

    def test_hollow_word_ooxml_flags(self):
        assert _format_masquerade_finding("docx", "zip") is not None
        assert _format_masquerade_finding("pptx", "zip") is not None

    def test_legacy_ext_with_ooxml_content_flags(self):
        assert _format_masquerade_finding("ole.doc", "docx") is not None

    def test_xlsb_like_not_flagged(self):
        # A binary workbook (.xlsx-family) is a valid ZIP without
        # xl/workbook.xml → classifies as "zip"; must NOT be a masquerade.
        assert _format_masquerade_finding("xlsx", "zip") is None

    def test_matching_types_not_flagged(self):
        assert _format_masquerade_finding("docx", "docx") is None
        assert _format_masquerade_finding("ole.doc", "ole.doc") is None


class TestEndToEnd:
    def test_ole_file_named_docx_is_flagged(self, tmp_path):
        # A legacy OLE binary renamed .docx — the masquerade malicious pattern.
        p = tmp_path / "invoice.docx"
        p.write_bytes(_OLE_MAGIC)
        report = Scanner(ScanConfig()).scan(str(p))
        masq = [
            f for f in report.findings
            if (f.evidence or {}).get("subtype") == "extension_content_mismatch"
        ]
        assert masq, "OLE-as-docx masquerade not flagged"
        assert masq[0].verdict_class == VerdictClass.REVIEW
        assert report.verdict.value in ("FLAG", "BLOCK")

    def test_legit_docx_not_flagged(self, tmp_path):
        import io
        import zipfile
        ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
            )
            zf.writestr(
                "_rels/.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
            )
            zf.writestr(
                "word/document.xml",
                f'<?xml version="1.0"?><w:document {ns}><w:body><w:p><w:r><w:t>Hi</w:t></w:r></w:p></w:body></w:document>',
            )
        p = tmp_path / "ok.docx"
        p.write_bytes(buf.getvalue())
        report = Scanner(ScanConfig()).scan(str(p))
        assert not [
            f for f in report.findings
            if (f.evidence or {}).get("subtype") == "extension_content_mismatch"
        ]
