from __future__ import annotations
import time


class Timer:
    """Context manager that records elapsed time in milliseconds."""

    def __init__(self) -> None:
        self._start = 0.0
        self._end = 0.0

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_args: object) -> None:
        self._end = time.perf_counter()

    @property
    def duration_ms(self) -> float:
        end = self._end if self._end > 0 else time.perf_counter()
        return (end - self._start) * 1000.0
