"""H.13 (0.4.8) — encryption / unscannable-content policy.

Content the scanner cannot decrypt is a blind spot. on_unscannable_verdict
lets a pipeline choose: warn (FLAG, default), block (fail closed), or allow
(INFO). The findings must use the evidence contract honestly — a reason +
debug steps, not a description masquerading as malicious_text.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.enums import Verdict, VerdictClass
from doc_firewall.scanner import Scanner

# Minimal PDF with an /Encrypt indirect reference (no real crypto needed —
# the fast scan keys on the /Encrypt N N R token).
_ENCRYPTED_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R /Encrypt 9 0 R /ID [<aa><bb>] >>\n%%EOF\n"
)


def _scan(policy: str | None):
    cfg = ScanConfig(profile="balanced")
    if policy is not None:
        cfg.on_unscannable_verdict = policy
    with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as t:
        t.write(_ENCRYPTED_PDF)
        path = t.name
    try:
        return Scanner(cfg).scan(path)
    finally:
        os.unlink(path)


def _enc_findings(report):
    return [
        f for f in report.findings
        if (f.evidence or {}).get("subtype") == "encrypted_unscannable"
    ]


class TestUnscannablePolicy:
    def test_finding_uses_contract_not_fake_malicious_text(self):
        r = _scan(None)
        enc = _enc_findings(r)
        assert enc
        ev = enc[0].evidence
        # Honest evidence: reason + debug steps, NOT a description pretending
        # to be extracted content.
        assert ev.get("evidence_unavailable_reason")
        assert ev.get("debug_steps")
        assert "malicious_text" not in ev

    def test_warn_default_flags(self):
        r = _scan(None)
        assert r.verdict == Verdict.FLAG
        assert _enc_findings(r)[0].verdict_class == VerdictClass.REVIEW

    def test_block_fails_closed(self):
        r = _scan("block")
        assert r.verdict == Verdict.BLOCK
        assert _enc_findings(r)[0].verdict_class == VerdictClass.BLOCK

    def test_allow_records_as_info(self):
        r = _scan("allow")
        enc = _enc_findings(r)
        assert enc
        assert enc[0].verdict_class == VerdictClass.INFO
        # INFO findings don't drive the verdict.
        assert r.verdict == Verdict.ALLOW
