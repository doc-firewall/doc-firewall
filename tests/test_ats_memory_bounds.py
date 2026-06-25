"""Regression: the advanced TF-IDF ATS detector must not blow up memory on an
adversarial document (0.5.0).

A malicious spreadsheet with tens of thousands of cells produced an extracted
text that `split('.')` turned into ~130k "sentences". `TfidfVectorizer` built
a sparse (n_sentences x vocab) matrix and the code then called `.todense()`,
materialising an n_sentences*vocab*8-byte array — ~150 GB on a stuffed
workbook. The fix caps the sentence count + vocabulary and computes the
per-term max on the SPARSE matrix (never densifies).
"""
from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.advanced_ats_manipulation import (
    _MAX_TFIDF_SENTENCES,
    AdvancedATSNLPDetector,
)

pytest.importorskip("sklearn")


def _rss_mb() -> float:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux reports kilobytes.
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def _adversarial_text(n_sentences: int = 80000) -> str:
    words = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
    parts = [
        f"the {words[i % 8]} role requires {words[(i // 8) % 8]} skills number {i} here"
        for i in range(n_sentences)
    ]
    return ". ".join(parts) + "."


class TestTfidfMemoryBounds:
    def test_huge_document_completes_fast_and_bounded(self):
        cfg = ScanConfig()
        cfg.enable_advanced_tfidf = True
        doc = ParsedDocument("x.txt", "txt", _adversarial_text(), {})

        before = _rss_mb()
        t0 = time.time()
        AdvancedATSNLPDetector().run(doc, cfg)  # must not OOM / hang
        elapsed = time.time() - t0
        grew = _rss_mb() - before

        # Pre-fix this densified to ~hundreds of GB and never returned.
        assert elapsed < 30, f"took {elapsed:.1f}s — possible blowup"
        assert grew < 1024, f"RSS grew {grew:.0f} MB — memory not bounded"

    def test_sentence_cap_is_modest(self):
        # The cap must be small enough that vocab * rows can't reach gigabytes.
        assert _MAX_TFIDF_SENTENCES <= 5000


class TestDetectionStillFires:
    def test_keyword_stuffing_still_detected(self):
        cfg = ScanConfig()
        cfg.enable_advanced_tfidf = True
        text = ("Senior software engineer with cloud experience. " * 40) + " ".join(
            f"Project {i} delivered on time and under budget with strong results."
            for i in range(30)
        )
        finds = AdvancedATSNLPDetector().run(ParsedDocument("r.txt", "txt", text, {}), cfg)
        assert any(f.threat_id.value == "T9_ATS_MANIPULATION" for f in finds)
