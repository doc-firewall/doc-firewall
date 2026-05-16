"""G.4 regression tests — eager pre-compile + content-hash pattern cache.

Asserts:
  1. PromptInjectionDetector / MetadataInjectionDetector / Advanced (AC)
     have their expensive state built at Scanner construction time.
  2. The pattern cache key is content-based, so two functionally-identical
     ScanConfig instances do NOT trigger a recompile.
  3. First-scan latency is not materially worse than steady-state latency
     (the regression the eager-compile is meant to remove).
"""
from __future__ import annotations

import os
import tempfile
import time

from doc_firewall.config import ScanConfig
from doc_firewall.scanner import Scanner
from doc_firewall.detectors.base import pattern_cache_key
from doc_firewall.detectors.prompt_injection import PromptInjectionDetector
from doc_firewall.detectors.metadata_injection import MetadataInjectionDetector
from doc_firewall.detectors.advanced_prompt_injection import (
    AdvancedPromptInjectionDetector,
)


def _make_doc(text: str = "This is a benign business document. " * 50) -> str:
    fd, path = tempfile.mkstemp(suffix=".html")
    with os.fdopen(fd, "w") as f:
        f.write(f"<html><body><p>{text}</p></body></html>")
    return path


class TestEagerCompile:
    def test_prompt_injection_compiled_at_init(self) -> None:
        sc = Scanner(ScanConfig(profile="balanced"))
        pi = next(
            d for d in sc.detectors if isinstance(d, PromptInjectionDetector)
        )
        assert hasattr(pi, "_compiled_patterns")
        assert len(pi._compiled_patterns) > 0
        assert hasattr(pi, "_compiled_key")

    def test_metadata_injection_compiled_at_init(self) -> None:
        sc = Scanner(ScanConfig(profile="balanced"))
        md = next(
            d for d in sc.detectors if isinstance(d, MetadataInjectionDetector)
        )
        assert hasattr(md, "_compiled_pi_patterns")
        assert len(md._compiled_pi_patterns) > 0

    def test_ahocorasick_built_at_init(self) -> None:
        sc = Scanner(ScanConfig(profile="balanced"))
        adv = next(
            d for d in sc.detectors
            if isinstance(d, AdvancedPromptInjectionDetector)
        )
        # balanced enables advanced_ahocorasick → automaton should be built
        assert adv._automaton is not None


class TestContentHashCache:
    def test_identical_configs_share_key(self) -> None:
        a = ScanConfig()
        b = ScanConfig()
        assert pattern_cache_key(a.prompt_injection_patterns) == \
            pattern_cache_key(b.prompt_injection_patterns)

    def test_new_config_object_does_not_recompile(self) -> None:
        """The old id(config) check recompiled on every new config object;
        the content hash must NOT."""
        pi = PromptInjectionDetector()
        cfg1 = ScanConfig()
        pi.prepare(cfg1)
        first_compiled = pi._compiled_patterns
        # A brand-new config object with identical patterns
        cfg2 = ScanConfig()
        pi._ensure_compiled(cfg2)
        # Same object reused — no recompile happened
        assert pi._compiled_patterns is first_compiled

    def test_changed_patterns_trigger_recompile(self) -> None:
        pi = PromptInjectionDetector()
        cfg = ScanConfig()
        pi.prepare(cfg)
        first = pi._compiled_patterns
        # Mutate the pattern set → key changes → recompile
        cfg.prompt_injection_patterns = {
            "x": [(r"\bnew custom pattern\b", 2.0)]
        }
        pi._ensure_compiled(cfg)
        assert pi._compiled_patterns is not first
        assert len(pi._compiled_patterns) == 1


class TestFirstScanLatency:
    def test_first_scan_not_much_slower_than_steady_state(self) -> None:
        """First scan should be within ~2x of steady-state median.

        G.4 isolates the *regex / Aho-Corasick compile* cost — that is what
        moves to __init__. Lazy ML model loading (sentence-transformers /
        BERT) is intentionally NOT eagerly loaded (multi-second, should stay
        first-use), so this test disables the ML text layers to measure the
        thing G.4 actually fixes.
        """
        cfg = ScanConfig(
            profile="balanced",
            enable_semantic_scans=False,   # no all-MiniLM lazy load
            enable_advanced_bert=False,    # no DeBERTa lazy load
            enable_semantic_nn=False,      # no NN model lazy load
        )
        sc = Scanner(cfg)
        path = _make_doc()
        try:
            t0 = time.perf_counter()
            sc.scan(path)
            first = time.perf_counter() - t0

            steady = []
            for _ in range(5):
                t = time.perf_counter()
                sc.scan(path)
                steady.append(time.perf_counter() - t)
            steady.sort()
            median = steady[len(steady) // 2]

            # Without eager compile the AC build (~5000 fuzzy variants) made
            # the first scan many times slower than steady-state. With G.4
            # the build is amortised into __init__, so first ≈ steady.
            assert first <= median * 2.0 + 0.05, (
                f"first={first*1000:.0f}ms median={median*1000:.0f}ms "
                "— eager-compile regression (AC/regex build leaked into "
                "first scan)"
            )
        finally:
            os.unlink(path)

    def test_ac_build_amortised_into_init(self) -> None:
        """Direct check: building the Scanner pays the AC cost; the first
        AdvancedPromptInjectionDetector.run() must not rebuild."""
        cfg = ScanConfig(profile="balanced", enable_advanced_bert=False)
        sc = Scanner(cfg)
        adv = next(
            d for d in sc.detectors
            if isinstance(d, AdvancedPromptInjectionDetector)
        )
        automaton_after_init = adv._automaton
        assert automaton_after_init is not None
        # Run once — must reuse the same automaton object, not rebuild.
        path = _make_doc()
        try:
            sc.scan(path)
        finally:
            os.unlink(path)
        assert adv._automaton is automaton_after_init
