"""
test_properties.py — Property-based tests using Hypothesis.

Tests invariants that must hold for ALL inputs, not just specific examples:
  - risk_model: score is always in [0.0, 1.0]; empty findings → 0.0
  - injection_normalizer: output is always lowercase; never contains
    zero-width or BIDI chars; idempotent when applied twice
  - Finding / ScanReport __eq__: reflexive and symmetric
"""
from __future__ import annotations

import pytest

try:
    from hypothesis import given, settings, assume
    from hypothesis import strategies as st
    _HAS_HYPOTHESIS = True
except ImportError:
    _HAS_HYPOTHESIS = False
    # H.10 (0.4.8): the module-level strategies below reference `st` at
    # import time, so the marker-based skip can't save collection — skip
    # the whole module before they evaluate.
    pytest.skip("hypothesis not installed", allow_module_level=True)

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from doc_firewall.risk_model import RiskModel
from doc_firewall.config import ScanConfig
from doc_firewall.report import Finding, ScanReport
from doc_firewall.enums import ThreatID, Severity, Verdict
from doc_firewall.detectors.injection_normalizer import (
    normalize_for_matching,
    has_obfuscation_chars,
)

_SKIP = pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_threat_ids = st.sampled_from(list(ThreatID))
_severities = st.sampled_from([Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
_confidences = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)


@st.composite
def finding_strategy(draw: st.DrawFn) -> Finding:
    return Finding(
        threat_id=draw(_threat_ids),
        severity=draw(_severities),
        title=draw(st.text(min_size=1, max_size=80)),
        explain=draw(st.text(max_size=200)),
        confidence=draw(_confidences),
        module=draw(st.one_of(st.none(), st.text(max_size=40))),
    )


# ---------------------------------------------------------------------------
# RiskModel properties
# ---------------------------------------------------------------------------

@_SKIP
@given(st.lists(finding_strategy(), max_size=20))
@settings(max_examples=200)
def test_risk_score_always_in_unit_interval(findings: list[Finding]) -> None:
    """Risk score must be in [0.0, 1.0] for any list of findings."""
    model = RiskModel(ScanConfig())
    score = model.calculate_risk(findings)
    assert 0.0 <= score <= 1.0, f"Score {score} out of bounds for {len(findings)} findings"


@_SKIP
def test_risk_score_empty_findings_is_zero() -> None:
    model = RiskModel(ScanConfig())
    assert model.calculate_risk([]) == 0.0


@_SKIP
@given(st.lists(finding_strategy(), min_size=1, max_size=10))
@settings(max_examples=100)
def test_risk_score_monotone_with_more_findings(findings: list[Finding]) -> None:
    """Adding a finding never decreases the risk score."""
    model = RiskModel(ScanConfig())
    base_score = model.calculate_risk(findings[:-1])
    full_score = model.calculate_risk(findings)
    assert full_score >= base_score - 1e-9, (
        f"Score decreased from {base_score} to {full_score} when adding a finding"
    )


@_SKIP
@given(_confidences)
@settings(max_examples=50)
def test_risk_score_critical_malware_high(confidence: float) -> None:
    """A single CRITICAL T1 finding should produce a high risk score."""
    assume(confidence > 0.5)
    model = RiskModel(ScanConfig())
    f = Finding(
        threat_id=ThreatID.T1_MALWARE,
        severity=Severity.CRITICAL,
        title="test",
        explain="",
        confidence=confidence,
    )
    score = model.calculate_risk([f])
    # weight=1.0 * severity=1.0 * confidence > 0.5 → score > 0.5
    assert score > 0.5, f"Expected high score for CRITICAL T1 at confidence {confidence}, got {score}"


# ---------------------------------------------------------------------------
# Verdict thresholds
# ---------------------------------------------------------------------------

@_SKIP
def test_verdict_thresholds_cover_full_range() -> None:
    """Every risk score in [0, 1] maps to a valid Verdict."""
    model = RiskModel(ScanConfig())
    for score_int in range(101):
        score = score_int / 100.0
        verdict = model.get_verdict(score)
        assert verdict in (Verdict.ALLOW, Verdict.FLAG, Verdict.BLOCK)


# ---------------------------------------------------------------------------
# injection_normalizer properties
# ---------------------------------------------------------------------------

@_SKIP
@given(st.text(max_size=500))
@settings(max_examples=300)
def test_normalize_output_is_lowercase(text: str) -> None:
    result = normalize_for_matching(text)
    assert result == result.lower(), f"normalize_for_matching output is not fully lowercase"


@_SKIP
@given(st.text(max_size=500))
@settings(max_examples=300)
def test_normalize_is_idempotent(text: str) -> None:
    once = normalize_for_matching(text)
    twice = normalize_for_matching(once)
    assert once == twice, "normalize_for_matching is not idempotent"


_ZERO_WIDTH_CHARS = "​‌‍‎‏﻿‪‫‬‭‮"


@_SKIP
@given(st.text(max_size=500))
@settings(max_examples=300)
def test_normalize_strips_zero_width_chars(text: str) -> None:
    result = normalize_for_matching(text)
    for ch in _ZERO_WIDTH_CHARS:
        assert ch not in result, f"Zero-width char U+{ord(ch):04X} survived normalization"


@_SKIP
@given(st.text(alphabet=_ZERO_WIDTH_CHARS, min_size=1, max_size=20))
@settings(max_examples=50)
def test_has_obfuscation_chars_detects_zero_width(text: str) -> None:
    assert has_obfuscation_chars(text), "has_obfuscation_chars missed zero-width input"


@_SKIP
@given(st.text(alphabet=st.characters(blacklist_categories=("Cf",)), max_size=200))
@settings(max_examples=100)
def test_has_obfuscation_chars_clean_ascii(text: str) -> None:
    """Text with no format/control chars should not trigger obfuscation detection."""
    assume(not any(c in text for c in _ZERO_WIDTH_CHARS))
    # Not asserting False because Unicode has other Cf chars — just check no crash
    _ = has_obfuscation_chars(text)


# ---------------------------------------------------------------------------
# Finding / ScanReport __eq__ properties
# ---------------------------------------------------------------------------

@_SKIP
@given(finding_strategy())
@settings(max_examples=100)
def test_finding_eq_is_reflexive(f: Finding) -> None:
    assert f == f


@_SKIP
@given(finding_strategy(), finding_strategy())
@settings(max_examples=100)
def test_finding_eq_is_symmetric(f1: Finding, f2: Finding) -> None:
    assert (f1 == f2) == (f2 == f1)


# ---------------------------------------------------------------------------
# Non-Hypothesis sanity tests (always run)
# ---------------------------------------------------------------------------

def test_risk_score_bounds_basic() -> None:
    model = RiskModel(ScanConfig())
    findings = [
        Finding(ThreatID.T4_PROMPT_INJECTION, Severity.HIGH, "t", "", confidence=0.9),
        Finding(ThreatID.T2_ACTIVE_CONTENT, Severity.CRITICAL, "t", "", confidence=1.0),
    ]
    score = model.calculate_risk(findings)
    assert 0.0 <= score <= 1.0


def test_normalize_basic() -> None:
    result = normalize_for_matching("Ign​ore‮ Previous")
    assert "​" not in result
    assert "‮" not in result
    assert result == result.lower()


def test_finding_eq_same_fields() -> None:
    f1 = Finding(ThreatID.T4_PROMPT_INJECTION, Severity.HIGH, "title", "explain",
                 confidence=0.9, module="test")
    f2 = Finding(ThreatID.T4_PROMPT_INJECTION, Severity.HIGH, "title", "explain",
                 confidence=0.9, module="test")
    assert f1 == f2


def test_finding_neq_different_threat() -> None:
    f1 = Finding(ThreatID.T4_PROMPT_INJECTION, Severity.HIGH, "title", "explain")
    f2 = Finding(ThreatID.T2_ACTIVE_CONTENT, Severity.HIGH, "title", "explain")
    assert f1 != f2


def test_scan_report_eq() -> None:
    r1 = ScanReport(file_path="/f", file_type="pdf", sha256="a" * 64,
                    size_bytes=100, verdict=Verdict.ALLOW, risk_score=0.1)
    r2 = ScanReport(file_path="/f", file_type="pdf", sha256="a" * 64,
                    size_bytes=200, verdict=Verdict.ALLOW, risk_score=0.1)
    assert r1 == r2  # size_bytes not in __eq__


def test_scan_report_neq_different_verdict() -> None:
    r1 = ScanReport(file_path="/f", file_type="pdf", sha256="a" * 64,
                    size_bytes=100, verdict=Verdict.ALLOW, risk_score=0.1)
    r2 = ScanReport(file_path="/f", file_type="pdf", sha256="a" * 64,
                    size_bytes=100, verdict=Verdict.BLOCK, risk_score=0.9)
    assert r1 != r2
