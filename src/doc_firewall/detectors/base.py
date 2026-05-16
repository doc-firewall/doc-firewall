from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List
from ..config import ScanConfig
from ..report import Finding
from ..analyzers.base import ParsedDocument


class Detector(ABC):
    name: str = "detector"

    def prepare(self, config: ScanConfig) -> None:
        """G.4: Eagerly build any expensive per-config state (compiled regex
        sets, Aho-Corasick automata) at Scanner construction time so the
        first scan is not slower than steady-state.

        Default is a no-op. Detectors with lazy initialisation override this
        and must keep `run()` able to lazily build state too, so a detector
        used standalone (without a Scanner) still works.
        """
        return None

    @abstractmethod
    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        raise NotImplementedError


def pattern_cache_key(patterns: dict) -> int:
    """Stable content hash for a `prompt_injection_patterns` dict.

    Used instead of `id(config)` so two functionally-identical ScanConfig
    instances share the compiled regex set instead of triggering a
    recompile (the old `id()` check recompiled on every new config object).
    """
    items = []
    for cat in sorted(patterns):
        rules = tuple(
            (str(p), float(w)) for p, w in patterns[cat]
        )
        items.append((cat, rules))
    return hash(tuple(items))
