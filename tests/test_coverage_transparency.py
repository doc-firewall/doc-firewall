"""H.11 (0.4.8) — coverage transparency tests.

A security scanner must not silently run in a degraded configuration. The
coverage report tells the caller which promised detection capabilities are
inactive, and require_full_coverage / required_capabilities let a pipeline
fail closed when they are.
"""
from __future__ import annotations

import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.capabilities import build_coverage_report
from doc_firewall.config import ScanConfig
from doc_firewall.enums import Verdict
from doc_firewall.scanner import Scanner


def _benign_docx(tmp_path) -> str:
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
            "<w:p><w:r><w:t>Benign quarterly report.</w:t></w:r></w:p>"
            "</w:body></w:document>",
        )
    path = str(tmp_path / "benign.docx")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    return path


def _malware_sigs_off() -> ScanConfig:
    """A config with T1 malware-signature detection forced off, regardless
    of what optional packages happen to be installed in the test env."""
    cfg = ScanConfig(profile="balanced")
    cfg.enable_yara = False
    cfg.enable_builtin_yara_rules = False
    cfg.antivirus_engine = None
    return cfg


class TestCoverageReport:
    def test_t4_baseline_only_without_ml(self):
        # Semantic/OCR/BERT injection layers are off by default → T4 has no
        # active primary capability.
        cov = build_coverage_report(ScanConfig(profile="balanced"))
        assert cov.degraded
        assert "T4" in cov.degraded_threats

    def test_malware_sigs_off_degrades_t1(self):
        cov = build_coverage_report(_malware_sigs_off())
        assert "T1" in cov.degraded_threats

    def test_summary_line_lists_remediation(self):
        cov = build_coverage_report(_malware_sigs_off())
        line = cov.summary_line()
        assert "REDUCED-COVERAGE" in line
        # Names at least one concrete remediation (a flag or pip extra).
        assert "enable_" in line or "pip install" in line or "antivirus" in line

    def test_threat_status_marks_baseline_only(self):
        status = build_coverage_report(_malware_sigs_off()).threat_status()
        assert status.get("T1") == "baseline-only"
        assert status.get("T4") == "baseline-only"

    def test_olefile_parsing_does_not_count_as_t1_detection(self):
        # Having olefile installed lets us PARSE legacy Office, but that is
        # not malware DETECTION — T1 must still degrade when YARA/AV are off.
        cov = build_coverage_report(_malware_sigs_off())
        ole = next(c for c in cov.capabilities if c.key == "ole")
        assert "T1" not in ole.primary_for
        assert "T1" in cov.degraded_threats

    def test_enabling_flag_without_package_stays_inactive(self):
        # semantic_nn flag on, but sentence_transformers absent in the test
        # venv → capability stays inactive and names the missing package.
        cfg = ScanConfig(profile="balanced")
        cfg.enable_semantic_nn = True
        cap = next(
            c for c in build_coverage_report(cfg).capabilities
            if c.key == "semantic_nn"
        )
        assert cap.enabled_flag
        if not cap.packages_present:
            assert not cap.active
            assert "sentence_transformers" in cap.missing_packages

    def test_antivirus_capability_tracks_engine(self):
        cfg = ScanConfig(profile="balanced")
        assert not next(c for c in build_coverage_report(cfg).capabilities
                        if c.key == "antivirus").active

        class _FakeAV:
            def scan_file(self, p):
                return {"infected": False}

        cfg.antivirus_engine = _FakeAV()
        av = next(c for c in build_coverage_report(cfg).capabilities if c.key == "antivirus")
        assert av.active


class TestReportCoverageAttached:
    def test_report_carries_coverage(self, tmp_path):
        r = Scanner(ScanConfig(profile="balanced")).scan(_benign_docx(tmp_path))
        assert r.coverage is not None
        assert "degraded" in r.coverage
        assert r.coverage["degraded"] is True

    def test_default_does_not_escalate_benign(self, tmp_path):
        # Transparency by default must NOT turn every benign doc into a FLAG;
        # escalation only happens when the caller opts in.
        r = Scanner(ScanConfig(profile="balanced")).scan(_benign_docx(tmp_path))
        assert r.verdict == Verdict.ALLOW
        assert not [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "reduced_coverage"
        ]


class TestFailClosed:
    def test_require_full_coverage_escalates(self, tmp_path):
        cfg = ScanConfig(profile="balanced")
        cfg.require_full_coverage = True
        r = Scanner(cfg).scan(_benign_docx(tmp_path))
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
        cov_findings = [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "reduced_coverage"
        ]
        assert cov_findings
        f = cov_findings[0]
        assert f.evidence["degraded_threats"]
        assert f.evidence["inactive_capabilities"]
        assert f.evidence["debug_steps"]

    def test_required_capability_missing_escalates(self, tmp_path):
        # Require semantic_nn, which is inactive in the test venv → escalate.
        cfg = ScanConfig(profile="balanced")
        cfg.required_capabilities = ["semantic_nn"]
        r = Scanner(cfg).scan(_benign_docx(tmp_path))
        cov_findings = [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "reduced_coverage"
        ]
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
        assert cov_findings
        assert "semantic_nn" in cov_findings[0].evidence["missing_required"]
