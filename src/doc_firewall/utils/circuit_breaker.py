from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Any, Callable, Optional


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is open."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Circuit breaker open for '{name}' — detector skipped")
        self.detector_name = name


class CircuitBreaker:
    """
    Three-state circuit breaker for a single detector.

    Transition table
    ----------------
    CLOSED    → failure_count reaches max_failures  → OPEN
    OPEN      → cooldown_s elapsed since last fault  → HALF_OPEN
    HALF_OPEN → next call succeeds                   → CLOSED
    HALF_OPEN → next call fails                      → OPEN (cooldown resets)

    Thread-safe: all state mutations are guarded by an internal lock.
    The breaker is instantiated once per detector in Scanner.__init__ and
    persists for the lifetime of the Scanner, so it accumulates failures
    across multiple scan() calls — which is the desired behaviour.
    """

    def __init__(
        self,
        name: str,
        max_failures: int = 3,
        cooldown_s: float = 60.0,
    ) -> None:
        self.name = name
        self.max_failures = max_failures
        self.cooldown_s = cooldown_s
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._resolved_state()

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Execute *fn* if the circuit allows it, updating state on outcome.

        Raises CircuitOpenError without calling *fn* when OPEN.
        Re-raises any exception from *fn* after recording the failure.
        """
        with self._lock:
            state = self._resolved_state()
            if state == CircuitState.OPEN:
                raise CircuitOpenError(self.name)

        try:
            result = fn(*args, **kwargs)
        except Exception:
            self.record_failure()
            raise

        self.record_success()
        return result

    def record_success(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.max_failures:
                self._state = CircuitState.OPEN

    # ── Internal ──────────────────────────────────────────────────────────────

    def _resolved_state(self) -> CircuitState:
        """Advance OPEN→HALF_OPEN if the cooldown has elapsed. Caller holds lock."""
        if (
            self._state == CircuitState.OPEN
            and self._last_failure_time is not None
            and time.monotonic() - self._last_failure_time >= self.cooldown_s
        ):
            self._state = CircuitState.HALF_OPEN
        return self._state
