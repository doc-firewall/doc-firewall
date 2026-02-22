from __future__ import annotations
import multiprocessing as mp
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class TimeoutResult:
    ok: bool
    value: Any = None
    error: Optional[str] = None
    timed_out: bool = False


def _worker(fn: Callable, args: tuple, kwargs: dict, q: mp.Queue) -> None:
    try:
        q.put(("ok", fn(*args, **kwargs)))
    except Exception as e:
        q.put(("err", f"{type(e).__name__}: {e}"))


def run_with_timeout(
    fn: Callable, args: tuple = (), kwargs: dict = None, timeout_ms: int = 30000
) -> TimeoutResult:
    if kwargs is None:
        kwargs = {}
    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    p = ctx.Process(target=_worker, args=(fn, args, kwargs, q), daemon=True)
    p.start()
    p.join(timeout_ms / 1000.0)
    if p.is_alive():
        p.terminate()
        p.join(0.5)
        return TimeoutResult(ok=False, timed_out=True, error="Timed out")
    if not q.empty():
        status, payload = q.get_nowait()
        if status == "ok":
            return TimeoutResult(ok=True, value=payload)
        return TimeoutResult(ok=False, error=payload)
    return TimeoutResult(ok=False, error="No result returned")
