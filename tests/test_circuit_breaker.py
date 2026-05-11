"""Tests for the per-detector circuit breaker."""
from __future__ import annotations

import time
from typing import List
from unittest.mock import patch

import pytest

from doc_firewall.utils.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)
from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.report import Finding
from doc_firewall.detectors.base import Detector


# ── Helpers ───────────────────────────────────────────────────────────────────

def _breaker(max_failures: int = 3, cooldown_s: float = 60.0) -> CircuitBreaker:
    return CircuitBreaker("test_detector", max_failures=max_failures, cooldown_s=cooldown_s)


def _ok() -> str:
    return "ok"


def _boom() -> None:
    raise RuntimeError("detector blew up")


# ── State machine unit tests ───────────────────────────────────────────────────

class TestCircuitBreakerStateMachine:
    def test_starts_closed(self):
        assert _breaker().state == CircuitState.CLOSED

    def test_successful_call_stays_closed(self):
        b = _breaker()
        result = b.call(_ok)
        assert result == "ok"
        assert b.state == CircuitState.CLOSED
        assert b.failure_count == 0

    def test_failure_increments_count(self):
        b = _breaker(max_failures=3)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        assert b.failure_count == 1
        assert b.state == CircuitState.CLOSED  # not yet open

    def test_opens_after_max_failures(self):
        b = _breaker(max_failures=3)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                b.call(_boom)
        assert b.state == CircuitState.OPEN

    def test_open_rejects_without_calling_fn(self):
        b = _breaker(max_failures=1)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        assert b.state == CircuitState.OPEN

        called = []
        with pytest.raises(CircuitOpenError) as exc_info:
            b.call(lambda: called.append(1))
        assert called == []  # fn was never invoked
        assert exc_info.value.detector_name == "test_detector"

    def test_consecutive_open_calls_all_raise(self):
        b = _breaker(max_failures=1)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        for _ in range(5):
            with pytest.raises(CircuitOpenError):
                b.call(_ok)

    def test_transitions_to_half_open_after_cooldown(self):
        b = _breaker(max_failures=1, cooldown_s=30.0)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        assert b.state == CircuitState.OPEN

        future_time = b._last_failure_time + 31.0  # type: ignore[operator]
        with patch("doc_firewall.utils.circuit_breaker.time.monotonic", return_value=future_time):
            assert b.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes_circuit(self):
        b = _breaker(max_failures=1, cooldown_s=30.0)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        assert b.state == CircuitState.OPEN

        base = b._last_failure_time
        with patch("doc_firewall.utils.circuit_breaker.time.monotonic", return_value=base + 31.0):
            assert b.state == CircuitState.HALF_OPEN
            result = b.call(_ok)
        assert result == "ok"
        assert b.state == CircuitState.CLOSED
        assert b.failure_count == 0

    def test_half_open_failure_reopens_circuit(self):
        b = _breaker(max_failures=1, cooldown_s=30.0)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        assert b.state == CircuitState.OPEN

        base = b._last_failure_time
        with patch("doc_firewall.utils.circuit_breaker.time.monotonic", return_value=base + 31.0):
            assert b.state == CircuitState.HALF_OPEN
            with pytest.raises(RuntimeError):
                b.call(_boom)
            # _last_failure_time now equals base+31; difference is 0 < 30 → OPEN
            assert b.state == CircuitState.OPEN

    def test_success_after_partial_failures_resets_count(self):
        b = _breaker(max_failures=3)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        with pytest.raises(RuntimeError):
            b.call(_boom)
        b.call(_ok)  # success resets
        assert b.failure_count == 0
        assert b.state == CircuitState.CLOSED

    def test_record_success_and_failure_public_api(self):
        b = _breaker(max_failures=2)
        b.record_failure()
        assert b.failure_count == 1
        b.record_failure()
        assert b.state == CircuitState.OPEN
        b.record_success()
        assert b.state == CircuitState.CLOSED
        assert b.failure_count == 0


# ── Scanner integration tests ─────────────────────────────────────────────────

class _BombDetector(Detector):
    """Always raises — used to trip a circuit breaker in the scanner."""
    name = "bomb_detector"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        raise RuntimeError("intentional detector failure")


class _GoodDetector(Detector):
    """Returns one finding every time."""
    name = "good_detector"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        from doc_firewall.enums import ThreatID, Severity
        return [
            Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.LOW,
                title="Good detector fired",
                explain="test",
                module="good_detector",
            )
        ]


class TestScannerCircuitBreaker:
    """Integration: scanner wires circuit breakers; skips open-circuit detectors."""

    def _make_scanner(self, max_failures: int = 3) -> "Scanner":  # noqa: F821
        from doc_firewall.scanner import Scanner
        from doc_firewall.config import ScanConfig

        config = ScanConfig()
        config.limits.circuit_breaker_max_failures = max_failures
        config.limits.circuit_breaker_cooldown_s = 999  # keep open during test
        s = Scanner(config=config)
        # Inject test detectors
        s.detectors = [_BombDetector(), _GoodDetector()]
        s._breakers = {
            det.name: CircuitBreaker(
                det.name,
                max_failures=max_failures,
                cooldown_s=999.0,
            )
            for det in s.detectors
        }
        return s

    def _doc(self) -> ParsedDocument:
        return ParsedDocument(
            file_path="test.txt",
            file_type="txt",
            text="Hello world",
            metadata={},
        )

    def _run_detectors(self, scanner) -> tuple[list, list]:
        """Run the detector loop directly; return (findings, skipped)."""
        doc = self._doc()
        skipped: list[str] = []
        findings: list[Finding] = []

        for det in scanner.detectors:
            breaker = scanner._breakers.get(det.name)
            if breaker is not None and breaker.state.value == "open":
                skipped.append(det.name)
                continue
            try:
                result = (
                    breaker.call(det.run, doc, scanner.config)
                    if breaker is not None
                    else det.run(doc, scanner.config)
                )
                findings.extend(result)
            except CircuitOpenError:
                skipped.append(det.name)
            except Exception:
                pass

        return findings, skipped

    def test_good_detector_always_fires(self):
        s = self._make_scanner()
        findings, skipped = self._run_detectors(s)
        titles = [f.title for f in findings]
        assert "Good detector fired" in titles
        assert "bomb_detector" not in skipped

    def test_bomb_trips_circuit_after_max_failures(self):
        s = self._make_scanner(max_failures=2)
        # Trip the bomb detector
        for _ in range(2):
            self._run_detectors(s)

        assert s._breakers["bomb_detector"].state == CircuitState.OPEN

    def test_open_circuit_is_skipped(self):
        s = self._make_scanner(max_failures=1)
        # One call trips it
        self._run_detectors(s)
        assert s._breakers["bomb_detector"].state == CircuitState.OPEN

        # Second call — bomb is skipped, good still fires
        findings, skipped = self._run_detectors(s)
        assert "bomb_detector" in skipped
        assert any(f.title == "Good detector fired" for f in findings)

    def test_good_detector_unaffected_by_sibling_circuit(self):
        s = self._make_scanner(max_failures=1)
        # Deliberately open bomb's circuit
        s._breakers["bomb_detector"].record_failure()  # force open with max=1
        findings, skipped = self._run_detectors(s)
        assert "bomb_detector" in skipped
        assert any(f.title == "Good detector fired" for f in findings)
