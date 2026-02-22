from __future__ import annotations
import time


class Timer:
    def __init__(self):
        self._start = 0.0
        self._end = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._end = time.perf_counter()

    @property
    def duration_ms(self) -> float:
        end = self._end if self._end > 0 else time.perf_counter()
        return (end - self._start) * 1000.0


def timer():
    return Timer()
