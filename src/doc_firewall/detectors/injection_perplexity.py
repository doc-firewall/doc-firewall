"""D.4 — Perplexity / character n-gram anomaly detector.

Defends against GCG-style adversarial-suffix prompt injection (Zou et al.,
2023).  GCG attacks append a tuned token suffix to a clean prompt to flip an
LLM's behaviour.  The suffix is gibberish-looking text that survives Aho-
Corasick / regex but stands out as a perplexity spike against natural prose.

This detector uses a built-in unigram log-probability table for ASCII letter
+ space + digit, then computes the rolling Shannon surprise of overlapping
character n-grams.  A window that is > N σ above the document mean fires
T4 LOW with `subtype = "perplexity_anomaly"`.

Pure stdlib + math.  No model, no API call, no large data file.
"""
from __future__ import annotations

import math
import re
from typing import List

from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity


# Letter-frequency table (English, source: Cornell University corpus —
# values widely re-used; embedded here so the detector has no data file).
# Frequencies sum to ~1.0 over [a-z ].  Anything else is mapped to a fixed
# floor.
_ENGLISH_UNIGRAM: dict[str, float] = {
    " ": 0.18, "e": 0.10268, "t": 0.07517, "a": 0.06532, "o": 0.06160,
    "n": 0.05712, "i": 0.05669, "s": 0.05317, "r": 0.04988, "h": 0.04979,
    "l": 0.03316, "d": 0.03283, "c": 0.02233, "u": 0.02272, "m": 0.02027,
    "f": 0.01983, "p": 0.01504, "g": 0.01625, "w": 0.01704, "y": 0.01428,
    "b": 0.01259, "v": 0.00796, "k": 0.00561, "x": 0.00141, "j": 0.00097,
    "q": 0.00084, "z": 0.00051,
}
_DIGIT_FLOOR = 0.005   # digits ~ 0.5 %
_PUNCT_FLOOR = 0.01    # punctuation ~ 1 %
_OOV_FLOOR = 0.0001    # anything else ~ 0.01 %

_NEG_LOG = {ch: -math.log2(p) for ch, p in _ENGLISH_UNIGRAM.items()}
_NEG_LOG_DIGIT = -math.log2(_DIGIT_FLOOR / 10)
_NEG_LOG_PUNCT = -math.log2(_PUNCT_FLOOR / 20)
_NEG_LOG_OOV = -math.log2(_OOV_FLOOR)


def _char_surprise(ch: str) -> float:
    lo = ch.lower()
    if lo in _NEG_LOG:
        return _NEG_LOG[lo]
    if ch.isdigit():
        return _NEG_LOG_DIGIT
    if ch in ".,!?;:'\"()[]{}-—–_":
        return _NEG_LOG_PUNCT
    return _NEG_LOG_OOV


_WINDOW_CHARS = 40         # GCG suffixes are 20-50 chars typically
_STEP = 20                 # overlapping by half
_MIN_DOC_CHARS = 200       # don't fire on tiny strings

# Precision gate (tuned against the 220-doc benign corpus, G.5).
# A relative z-score alone flags benign numeric / abbreviation / code-token
# windows. A real GCG adversarial suffix is ALSO (a) absolutely high-surprise,
# (b) dense with symbols / digits / mid-word uppercase, and (c) SUSTAINED over
# multiple adjacent windows. All three are required.
_SIGMA_THRESHOLD = 4.0     # sharp relative anomaly (not natural variance)
_ABS_SURPRISE_FLOOR = 4.9  # bits/char — benign English ≈ 4.0–4.6 in this model
_SYMBOL_RATIO_FLOOR = 0.22  # GCG suffixes interleave punctuation/digits/caps
_SUSTAINED_WINDOWS = 2     # ≥2 adjacent anomalous windows (≈60+ chars)
_EXTREME_SYMBOL_RATIO = 0.40  # single-window shortcut for blatant gibberish


def _symbol_ratio(s: str) -> float:
    """Fraction of chars that are NOT a lowercase letter or a single space.

    GCG suffixes are dense with punctuation, digits, and mid-word uppercase;
    natural English prose is overwhelmingly lowercase letters + spaces, so
    this cleanly separates the two without a dictionary."""
    if not s:
        return 0.0
    hard = sum(1 for c in s if not (c.islower() or c == " "))
    return hard / len(s)


_VOWELS = set("aeiouy")


def _plausible_word_ratio(s: str) -> float:
    """Fraction of whitespace tokens that look like real words.

    The strongest dictionary-free discriminator between dense *legal /
    resume / contract formatting* (which has a high symbol ratio AND high
    surprise from quotes, parentheses, ALL-CAPS headers, numbered clauses,
    em-dashes and date ranges — structurally GCG-like at the character
    level) and an actual GCG adversarial suffix:

      • Legal / prose tokens are REAL WORDS — alphabetic, contain a vowel,
        2–15 chars (after stripping bounding punctuation).
      • GCG-suffix tokens are non-words — `}{>!]`, `xQ9z`, `.](`, random
        case/symbol salad.

    Returns plausible_word_tokens / total_tokens. Natural text scores high
    (~0.6–0.9); a GCG suffix scores low (< ~0.25)."""
    toks = s.split()
    if not toks:
        return 1.0  # no tokens → treat as natural (don't fire)
    plausible = 0
    for t in toks:
        core = t.strip("\"'()[]{}.,;:!?-—–_*/\\|<>")
        if not core:
            continue
        if (
            2 <= len(core) <= 15
            and core.isalpha()
            and any(ch in _VOWELS for ch in core.lower())
        ):
            plausible += 1
    return plausible / len(toks)


# Below this plausible-word ratio the window is non-language gibberish
# (GCG / encoded payload); at or above it the window is natural text even
# if it is symbol-dense (legal boilerplate, resumes), so suppress.
_PLAUSIBLE_WORD_FLOOR = 0.30


class InjectionPerplexityDetector(Detector):
    """D.4 — fires when a sliding character window is significantly more
    surprising than the document's natural baseline.

    Designed to flag GCG suffixes and Base64/hex-encoded payloads embedded in
    otherwise natural prose.  Confidence is intentionally low (LOW severity)
    — this is a *soft* signal that contributes to the risk score but should
    not fire BLOCK on its own.
    """

    name = "injection_perplexity"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_perplexity_check", True):
            return []

        text = doc.text or ""
        if len(text) < _MIN_DOC_CHARS:
            return []

        # Cap scan to first 200K chars to bound cost on huge documents.
        text = text[:200_000]

        # Normalise whitespace BEFORE scoring. Document formatting (newlines,
        # tab/space indentation in resumes, contracts, READMEs) otherwise
        # registers as high-surprise OOV runs and inflates the symbol ratio,
        # producing false positives on perfectly benign formatted prose. A
        # real GCG suffix remains high-surprise after this step — its signal
        # is punctuation/case/non-words, not layout.
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) < _MIN_DOC_CHARS:
            return []

        # Precompute per-character surprise once.
        surprises = [_char_surprise(c) for c in text]

        # Document mean / variance over disjoint chunks (cheap).
        chunk = 200
        chunk_means: list[float] = []
        for s in range(0, len(text), chunk):
            seg = surprises[s: s + chunk]
            if len(seg) >= 50:
                chunk_means.append(sum(seg) / len(seg))
        if len(chunk_means) < 5:
            return []

        mu = sum(chunk_means) / len(chunk_means)
        var = sum((x - mu) ** 2 for x in chunk_means) / len(chunk_means)
        sigma = math.sqrt(var) if var > 0 else 0.0
        if sigma == 0.0:
            return []

        # Sliding-window scan. A window is "anomalous" only when it is
        # sharply above the document mean (z) AND absolutely high-surprise
        # AND structurally GCG-like (symbol/digit/caps density). We then
        # require the anomaly to be SUSTAINED across adjacent windows, OR a
        # single window to be blatantly gibberish (extreme symbol ratio).
        anomalous: list[tuple[int, float, float, float]] = []  # (pos,z,mean,sym)
        for s in range(0, len(text) - _WINDOW_CHARS, _STEP):
            win = surprises[s: s + _WINDOW_CHARS]
            m = sum(win) / _WINDOW_CHARS
            z = (m - mu) / sigma
            if z < _SIGMA_THRESHOLD or m < _ABS_SURPRISE_FLOOR:
                continue
            window_text = text[s: s + _WINDOW_CHARS]
            sym = _symbol_ratio(window_text)
            if sym < _SYMBOL_RATIO_FLOOR:
                continue
            # Dictionary-free language gate: suppress windows that are still
            # mostly real words (legal boilerplate, resumes, numbered
            # clauses) even when symbol-dense. Only non-language gibberish
            # (GCG / encoded payload) passes.
            if _plausible_word_ratio(window_text) >= _PLAUSIBLE_WORD_FLOOR:
                continue
            anomalous.append((s, z, m, sym))

        if not anomalous:
            return []

        # Sustained-region check: count adjacent anomalous windows (positions
        # differing by exactly _STEP form a contiguous high-surprise block).
        anomalous.sort()
        best = max(anomalous, key=lambda a: a[1])  # highest z
        run = 1
        positions = [a[0] for a in anomalous]
        pos_set = set(positions)
        # Length of the contiguous run containing `best`.
        p = best[0]
        while (p - _STEP) in pos_set:
            run += 1
            p -= _STEP
        p = best[0]
        while (p + _STEP) in pos_set:
            run += 1
            p += _STEP

        sustained = run >= _SUSTAINED_WINDOWS
        blatant = best[3] >= _EXTREME_SYMBOL_RATIO
        if not (sustained or blatant):
            return []

        best_pos, best_z, best_mean, _best_sym = best
        snippet = text[best_pos: best_pos + _WINDOW_CHARS]

        return [
            Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.LOW,
                title="Prompt Injection — Perplexity Anomaly (Possible GCG Suffix)",
                explain=(
                    f"A {_WINDOW_CHARS}-char window has mean character "
                    f"surprise {best_mean:.2f} bits — {best_z:.1f}σ above the "
                    f"document mean ({mu:.2f}). High-surprise gibberish "
                    "interleaved with natural prose is the GCG-style "
                    "adversarial-suffix injection signature."
                ),
                evidence={
                    "subtype": "perplexity_anomaly",
                    "z_score": round(best_z, 2),
                    "window_mean_bits": round(best_mean, 2),
                    "doc_mean_bits": round(mu, 2),
                    "position": best_pos,
                    "malicious_text": snippet,
                },
                module=self.name,
                confidence=0.55,
            )
        ]
