"""PII is a privacy notice, not a malicious-document threat (0.5.0).

Real documents — résumés, finance spreadsheets, contracts — legitimately
contain names, emails, phone numbers, and card numbers. Driving the threat
verdict off that flagged ~88–100% of a real benign corpus. So the PII detector
emits an INFO-class T8 finding: fully reported (with severity preserved), but
it does NOT push the verdict to FLAG/BLOCK on its own.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.pii import PiiDetector
from doc_firewall.enums import ThreatID, VerdictClass
from doc_firewall.risk_model import RiskModel

# A benign document that legitimately contains PII (a résumé-style record).
_PII_TEXT = (
    "Jane Doe — Senior Engineer. Email: jane.doe@example.com. "
    "Phone: (415) 555-0137. Card on file: 4111 1111 1111 1111."
)


def _doc(text: str) -> ParsedDocument:
    return ParsedDocument(file_path="r.txt", file_type="txt", text=text, metadata={})


def _findings():
    return PiiDetector().run(_doc(_PII_TEXT), ScanConfig())


class TestPiiIsInfoClass:
    def test_pii_detected_but_info_class(self):
        finds = _findings()
        assert finds, "PII should still be detected and reported"
        pii = [f for f in finds if f.threat_id == ThreatID.T8_METADATA_INJECTION]
        assert pii, "expected a T8 PII finding"
        for f in pii:
            assert f.verdict_class == VerdictClass.INFO, (
                "PII must be INFO-class so it doesn't drive the verdict"
            )

    def test_pii_does_not_drive_flag_verdict(self):
        # A document whose ONLY findings are PII must verdict ALLOW.
        finds = _findings()
        assert all(f.verdict_class == VerdictClass.INFO for f in finds)
        verdict = RiskModel(ScanConfig()).get_verdict(0.0, finds)
        assert verdict.value == "ALLOW", f"PII-only doc should ALLOW, got {verdict}"

    def test_pii_excluded_from_risk_score(self):
        # INFO-class findings are recorded for audit but don't score.
        finds = _findings()
        assert RiskModel(ScanConfig()).calculate_risk(finds) == 0.0
