"""H.6 (0.4.8) — stage-timeout escalation tests.

A stage timeout means the document was never fully scanned; the scan must
not silently ALLOW. Default escalates to FLAG; on_timeout_verdict='block'
fails closed.
"""
from __future__ import annotations

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.enums import Severity, ThreatID, Verdict, VerdictClass
from doc_firewall.scanner import Scanner


def _minimal_docx(tmp_path) -> str:
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            "</Types>",
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
            "<w:p><w:r><w:t>Plain benign content.</w:t></w:r></w:p>"
            "</w:body></w:document>",
        )
    path = str(tmp_path / "benign.docx")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


class TestTimeoutFinding:
    def test_finding_shape_warn(self):
        s = Scanner(ScanConfig(profile="balanced"))
        f = s._timeout_finding("detectors", 600000)
        assert f.threat_id == ThreatID.T6_DOS
        assert f.severity == Severity.MEDIUM
        assert f.verdict_class == VerdictClass.REVIEW
        assert f.evidence["subtype"] == "scan_timeout"
        assert f.evidence["evidence_unavailable_reason"]
        assert any("TIMEOUT_MS" in step for step in f.evidence["debug_steps"])

    def test_finding_block_when_fail_closed(self):
        cfg = ScanConfig(profile="balanced")
        cfg.on_timeout_verdict = "block"
        f = Scanner(cfg)._timeout_finding("parse", 600000)
        assert f.verdict_class == VerdictClass.BLOCK

    def test_default_timeouts_doubled(self):
        limits = ScanConfig().limits
        assert limits.fast_scan_timeout_ms == 600000
        assert limits.parse_timeout_ms == 600000
        assert limits.format_checks_timeout_ms == 600000
        assert limits.detectors_timeout_ms == 600000
        assert limits.antivirus_timeout_ms == 600000
        assert limits.docling_subprocess_timeout_s == 540


class TestTimeoutEscalationEndToEnd:
    def test_detectors_timeout_escalates_to_flag(self, tmp_path):
        path = _minimal_docx(tmp_path)
        cfg = ScanConfig(profile="balanced")
        cfg.limits.detectors_timeout_ms = 0  # force immediate stage timeout
        r = Scanner(cfg).scan(path)
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
        assert "detectors" in r.metadata.get("timed_out_stages", [])
        timeout_findings = [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "scan_timeout"
        ]
        assert timeout_findings
        assert "incomplete" in timeout_findings[0].title.lower()

    def test_detectors_timeout_blocks_when_fail_closed(self, tmp_path):
        path = _minimal_docx(tmp_path)
        cfg = ScanConfig(profile="balanced")
        cfg.on_timeout_verdict = "block"
        cfg.limits.detectors_timeout_ms = 0
        r = Scanner(cfg).scan(path)
        assert r.verdict == Verdict.BLOCK

    @pytest.mark.benign
    def test_no_timeout_no_finding(self, tmp_path):
        path = _minimal_docx(tmp_path)
        r = Scanner(ScanConfig(profile="balanced")).scan(path)
        assert not [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "scan_timeout"
        ]
        assert r.verdict == Verdict.ALLOW
