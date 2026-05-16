"""G.5 — D.4 perplexity detector is opt-in and precision-hardened.

The 220-doc benign corpus (test_benign_corpus_200.py) empirically showed
the perplexity heuristic cannot achieve both <=1% FP and useful GCG recall
using character statistics alone, because real GCG suffixes interleave
word-like tokens with symbols and overlap dense legal/contract formatting.

Resolution (evidence-driven): the detector is OFF by default. When an
operator knowingly enables it, the hardened gates (absolute surprise floor +
symbol ratio + sustained region + plausible-word ratio) keep it quiet on
benign prose while still flagging non-word gibberish / encoded blobs.
"""
from __future__ import annotations

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.injection_perplexity import InjectionPerplexityDetector

_CLEAN = (
    "Please summarise the quarterly report and list the action items for "
    "the team before the next planning meeting. "
) * 5
_GIBBERISH = (
    " }{>!]xQ9z#@*&^%~]}>!*(){}|\\pQ#zR}{>!xK9z}{>!]xQ9z#@*&^%~]}>!*(){}"
    "|\\pQ#zR}{>!xK9z}{>!]xQ9z#@*&^ "
)


def _doc(text: str) -> ParsedDocument:
    return ParsedDocument("x", "txt", text, {})


def test_perplexity_off_by_default() -> None:
    """Default config must NOT run the perplexity detector (opt-in)."""
    pp = InjectionPerplexityDetector()
    doc = _doc(_CLEAN + _GIBBERISH + _CLEAN)
    assert pp.run(doc, ScanConfig()) == []


def test_perplexity_fires_on_gibberish_when_enabled() -> None:
    pp = InjectionPerplexityDetector()
    doc = _doc(_CLEAN + _GIBBERISH + _CLEAN)
    findings = pp.run(doc, ScanConfig(enable_perplexity_check=True))
    assert findings, "perplexity should fire on sustained non-word gibberish"
    assert findings[0].evidence.get("subtype") == "perplexity_anomaly"


def test_perplexity_silent_on_benign_prose_when_enabled() -> None:
    pp = InjectionPerplexityDetector()
    doc = _doc(_CLEAN * 3)
    assert pp.run(doc, ScanConfig(enable_perplexity_check=True)) == []


def test_perplexity_silent_on_legal_formatting_when_enabled() -> None:
    """The exact pattern that drove the G.5 false positives: dense legal /
    contract boilerplate with quotes, numbered clauses, ALL-CAPS headers."""
    legal = (
        'This Services Agreement ("Agreement") is entered into between the '
        'Provider ("Provider") and the counterparty identified in the Order '
        'Form ("Client"). 1. SCOPE. Provider shall deliver the services in '
        'the Statement of Work. 2. PAYMENT. Client agrees to pay all '
        'undisputed invoices within 30 days. 3. CONFIDENTIALITY. Each party '
        'shall protect the other party\'s information. 4. TERMINATION. '
        "Either party may terminate for material breach. " * 3
    )
    pp = InjectionPerplexityDetector()
    findings = pp.run(_doc(legal), ScanConfig(enable_perplexity_check=True))
    assert findings == [], (
        f"perplexity false-fired on benign legal boilerplate: "
        f"{[f.evidence.get('malicious_text') for f in findings]}"
    )
