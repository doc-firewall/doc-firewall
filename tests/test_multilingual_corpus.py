"""W3.1 (0.5.0) — end-to-end per-language recall on the multilingual corpus.

Proves that a non-English injection in body / hidden text / metadata is
caught through the full Scanner with the DEFAULT install (no ML extras),
and reports per-language / per-surface recall.
"""
from __future__ import annotations

import os
import sys
import tempfile
from collections import defaultdict

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from multilingual_corpus_data import INJECTION, SURFACES, generate_multilingual_corpus

from doc_firewall.config import ScanConfig
from doc_firewall.enums import Verdict
from doc_firewall.scanner import Scanner

# Default-install recall floor (no [ml]): Layers A (script-mixing) + B
# (multilingual keywords) should catch the great majority across surfaces.
_RECALL_FLOOR = 0.90


def _scan_corpus():
    scanner = Scanner(ScanConfig(profile="balanced"))
    results = []
    with tempfile.TemporaryDirectory() as td:
        for case_id, lang, surface, data in generate_multilingual_corpus():
            path = os.path.join(td, f"{case_id}.docx")
            with open(path, "wb") as f:
                f.write(data)
            r = scanner.scan(path)
            results.append((lang, surface, r.verdict != Verdict.ALLOW, r))
    return results


@pytest.fixture(scope="module")
def corpus_results():
    return _scan_corpus()


@pytest.mark.adversarial
class TestMultilingualRecall:
    def test_overall_recall_meets_floor(self, corpus_results):
        detected = sum(1 for _l, _s, ok, _r in corpus_results if ok)
        total = len(corpus_results)
        recall = detected / total
        assert recall >= _RECALL_FLOOR, (
            f"multilingual recall {recall:.1%} < {_RECALL_FLOOR:.0%}; "
            f"misses: {[(lang, s) for lang, s, ok, _ in corpus_results if not ok]}"
        )

    def test_every_language_detected_somewhere(self, corpus_results):
        by_lang = defaultdict(list)
        for lang, _surface, ok, _r in corpus_results:
            by_lang[lang].append(ok)
        undetected = [lang for lang, oks in by_lang.items() if not any(oks)]
        assert not undetected, f"languages never detected on any surface: {undetected}"

    def test_all_languages_and_surfaces_present(self, corpus_results):
        langs = {lang for lang, _s, _ok, _r in corpus_results}
        surfaces = {s for _lang, s, _ok, _r in corpus_results}
        assert langs == set(INJECTION)
        assert surfaces == set(SURFACES)

    def test_hidden_surface_carries_evidence(self, corpus_results):
        # Hidden-surface detections must carry the offending text (contract).
        for lang, surface, ok, r in corpus_results:
            if surface == "hidden" and ok:
                assert any(
                    (f.evidence or {}).get("malicious_text")
                    for f in r.findings
                    if (f.evidence or {}).get("subtype")
                    in ("hidden_foreign_script", "multilingual_injection")
                ), f"{lang}/hidden has no evidence-bearing finding"
