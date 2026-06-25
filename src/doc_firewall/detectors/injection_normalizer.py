"""
injection_normalizer.py

Shared text normalization layer for all prompt-injection detectors.

Design goal: strip / collapse every obfuscation trick that an attacker might
use to hide a known injection phrase from an exact-match or pattern detector —
without silently skipping detection the way the old early-exit did.

Transformations applied (in order):
  1. Remove zero-width and invisible Unicode characters (U+200B..U+200F, U+FEFF,
     BIDI overrides U+202A..U+202E, U+2066..U+2069)
  2. Normalize Unicode to NFC form and map common homoglyphs to their ASCII
     equivalents (Cyrillic/Greek lookalikes, fullwidth ASCII, etc.)
  3. Collapse whitespace (tabs, newlines, multiple spaces → single space)
  4. Lowercase

The raw (un-normalized) text is preserved separately so the BERT classifier can
still receive naturally-worded sentences rather than collapsed lowercase strings.
"""

from __future__ import annotations

import re
import unicodedata

from ..utils.unicode_norm import _MATH_SCRIPT_MAP, _STRIP_TABLE  # D.5/F.5

# ── 1. Zero-width / invisible / BIDI characters ─────────────────────────────

_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"   # zero-width space/non-joiner/joiner/LRM/RLM
    r"\ufeff"                             # BOM / zero-width no-break space
    r"\u202a\u202b\u202c\u202d\u202e"    # LRE, RLE, PDF, LRO, RLO
    r"\u2066\u2067\u2068\u2069]",        # LRI, RLI, FSI, PDI
    re.UNICODE,
)

# ── 2. Homoglyph map ─────────────────────────────────────────────────────────
# Covers the most commonly exploited confusables (Cyrillic → Latin, Greek →
# Latin, fullwidth → ASCII).  Intentionally conservative — only add a mapping
# when you have evidence it's used in injection attacks.

_HOMOGLYPH_MAP: dict[int, str] = {
    # Cyrillic lowercase — look identical to Latin lowercase
    ord("а"): "a",  ord("е"): "e",  ord("о"): "o",  ord("р"): "p",
    ord("с"): "c",  ord("х"): "x",  ord("у"): "y",  ord("і"): "i",
    ord("ё"): "e",  ord("ѕ"): "s",  ord("ј"): "j",  ord("ԁ"): "d",
    ord("ь"): "b",  ord("ѵ"): "v",  ord("ԛ"): "q",  ord("ԝ"): "w",
    ord("ӏ"): "i",  ord("ӕ"): "ae",
    # B.11: Cyrillic UPPERCASE homoglyphs — the most commonly abused set.
    # Each maps to its lowercase Latin lookalike (step 5 lowercases everything).
    ord("А"): "a",  # U+0410 ≡ Latin A
    ord("В"): "b",  # U+0412 ≡ Latin B
    ord("С"): "c",  # U+0421 ≡ Latin C
    ord("Е"): "e",  # U+0415 ≡ Latin E
    ord("Н"): "h",  # U+041D ≡ Latin H
    ord("К"): "k",  # U+041A ≡ Latin K
    ord("М"): "m",  # U+041C ≡ Latin M
    ord("О"): "o",  # U+041E ≡ Latin O
    ord("Р"): "r",  # U+0420 ≡ Latin R (NB: lowercase р → p, uppercase Р → r)
    ord("Т"): "t",  # U+0422 ≡ Latin T
    ord("Х"): "x",  # U+0425 ≡ Latin X
    ord("Ѕ"): "s",  # U+0405 ≡ Latin S
    ord("Ј"): "j",  # U+0408 ≡ Latin J
    ord("І"): "i",  # U+0406 ≡ Latin I
    ord("Ү"): "y",  # U+04AE
    ord("Ԛ"): "q",  # U+051A
    ord("Ԝ"): "w",  # U+051C
    # Greek lowercase
    ord("α"): "a",  ord("β"): "b",  ord("γ"): "y",  ord("ε"): "e",
    ord("ζ"): "z",  ord("η"): "n",  ord("ι"): "i",  ord("κ"): "k",
    ord("μ"): "u",  ord("ν"): "v",  ord("ο"): "o",  ord("ρ"): "p",
    ord("τ"): "t",  ord("υ"): "u",  ord("χ"): "x",  ord("σ"): "o",
    ord("ω"): "w",
    # Greek uppercase
    ord("Α"): "a",  ord("Β"): "b",  ord("Ε"): "e",
    ord("Ζ"): "z",  ord("Η"): "h",  ord("Ι"): "i",  ord("Κ"): "k",
    ord("Μ"): "m",  ord("Ν"): "n",  ord("Ο"): "o",  ord("Ρ"): "p",
    ord("Τ"): "t",  ord("Υ"): "y",  ord("Χ"): "x",
    ord("Σ"): "e",  ord("Φ"): "o",  ord("Ψ"): "y",
    # Fullwidth ASCII (！ … ～)
    **{cp: chr(cp - 0xFEE0) for cp in range(0xFF01, 0xFF5F)},
    # F.1: Armenian uppercase (skews left of Latin in confusable rank lists)
    ord("Ա"): "u",  # U+0531 — visually similar to inverted U
    ord("Ո"): "n",  # U+0548 — looks like Latin N
    ord("Տ"): "s",  # U+054F
    # F.1: Cherokee uppercase — frequently used in URL spoofing
    ord("Ꭺ"): "a",  ord("Ᏼ"): "b",  ord("Ꭼ"): "e",
    ord("Ꮎ"): "h",  ord("Ꮤ"): "w",  ord("Ꮩ"): "v",  ord("Ꭱ"): "r",
    ord("Ꮓ"): "z",
    # F.1: Coptic — close visual match for several Latin letters
    ord("Ⲁ"): "a",  ord("Ⲃ"): "b",  ord("Ⲉ"): "e",  ord("Ⲏ"): "h",
    ord("Ⲓ"): "i",  ord("Ⲕ"): "k",  ord("Ⲙ"): "m",  ord("Ⲛ"): "n",
    ord("Ⲟ"): "o",  ord("Ⲣ"): "p",  ord("Ⲧ"): "t",  ord("Ⲭ"): "x",
    # F.1: IPA / phonetic latin lookalikes
    ord("ɑ"): "a",  ord("ɡ"): "g",  ord("ɪ"): "i",  ord("ɴ"): "n",
    ord("ʀ"): "r",  ord("ʟ"): "l",  ord("ᴀ"): "a",  ord("ᴇ"): "e",
    ord("ᴏ"): "o",  ord("ᴜ"): "u",
    # Latin look-alikes
    ord("ı"): "i",  ord("ℓ"): "l",
    # F.1: Letterlike Symbols (U+2100+) NOT folded by NFKC
    ord("ℐ"): "i",  ord("ℑ"): "i",  ord("ℒ"): "l",  ord("ℓ"): "l",
    ord("ℛ"): "r",  ord("ℜ"): "r",  ord("ℬ"): "b",  ord("ℯ"): "e",
    ord("ℰ"): "e",  ord("ℱ"): "f",  ord("ℳ"): "m",  ord("ℴ"): "o",
    ord("ℋ"): "h",  ord("ℌ"): "h",  ord("ℍ"): "h",  ord("ℒ"): "l",
    ord("ℙ"): "p",  ord("ℚ"): "q",  ord("ℝ"): "r",  ord("ℂ"): "c",
    ord("ℤ"): "z",
    # F.1: superscript / subscript letters (some NFKC-folded, some not)
    ord("ᵃ"): "a",  ord("ᵇ"): "b",  ord("ᶜ"): "c",  ord("ᵈ"): "d",
    ord("ᵉ"): "e",  ord("ᵍ"): "g",  ord("ʰ"): "h",  ord("ⁱ"): "i",
    ord("ʲ"): "j",  ord("ᵏ"): "k",  ord("ˡ"): "l",  ord("ᵐ"): "m",
    ord("ⁿ"): "n",  ord("ᵒ"): "o",  ord("ᵖ"): "p",  ord("ʳ"): "r",
    ord("ˢ"): "s",  ord("ᵗ"): "t",  ord("ᵘ"): "u",  ord("ᵛ"): "v",
    ord("ʷ"): "w",  ord("ˣ"): "x",  ord("ʸ"): "y",  ord("ᶻ"): "z",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)

# F.3: inter-letter separator handling.
# We use TWO patterns:
#  (a) Single-char-separated obfuscation: "i-g-n-o-r-e" → "ignore"
#      Pattern matches \w(sep\w){2,} so only fires on 3+ single-char chains.
#      Separator is *removed* so the result reaches AC as the contiguous word.
#  (b) Multi-letter-separated obfuscation: "ignore-all-previous" → "ignore all
#      previous". Separator between two letters is *replaced with a space* so
#      the AC dictionary (which stores phrases with spaces) still matches.
_SEP_SINGLE_COLLAPSE_RE = re.compile(
    r"(?<!\w)\w(?:[\-_.·•]\w){2,}(?!\w)"
)
_SEP_INTERLETTER_RE = re.compile(r"(?<=[A-Za-z])[\-_.·•](?=[A-Za-z])")
_SEP_STRIP_RE = re.compile(r"[\-_.·•]")
# F.5: single-char-spacing collapse parallel to B.16 — handles "i g n o r e"
# style obfuscation that surfaces after ZW chars are converted to spaces.
_SPACE_SINGLE_COLLAPSE_RE = re.compile(r"(?<!\w)\w(?:[ \t ]\w){2,}(?!\w)")
_SPACE_STRIP_RE = re.compile(r"[ \t ]")

# ── Public API ────────────────────────────────────────────────────────────────


def normalize_for_matching(text: str) -> str:
    """Return a normalized, lowercased copy of *text* suitable for exact /
    pattern matching.  The original is never mutated.

    Steps:
      1. Strip zero-width / BIDI characters
      2. Map homoglyphs to ASCII equivalents
      3. Unicode NFC normalization
      4. Collapse whitespace
      5. Lowercase
    """
    # Step 1 — replace invisible chars with a space so that an attacker who
    # inserts U+200B *between* letters of a word ("ign\u200bore") doesn't
    # accidentally merge two surrounding words when the char is removed.
    # Step 0 — F.5: strip tag chars / variation selectors (invisible).
    cleaned = text.translate(_STRIP_TABLE)

    # Step 1a — F.5: collapse intra-word ZW obfuscation FIRST, before any
    # bulk ZW replacement. Pattern: 3+ single letters separated by ZW chars
    # within one word ("i[zw]g[zw]n[zw]o[zw]r[zw]e") → "ignore". This
    # preserves real word-boundary spaces because the regex requires the
    # entire run to be word-char + ZW-only, not crossing any real space.
    _ZW_CLASS = "[​‌‍‎‏﻿‪-‮⁦-⁩]"
    cleaned = re.sub(
        rf"(?<!\w)\w(?:{_ZW_CLASS}+\w){{2,}}(?!\w)",
        lambda m: re.sub(_ZW_CLASS, "", m.group(0)),
        cleaned,
    )

    # Step 1b — Any remaining ZW between two word chars → SPACE (handles
    # attacker-replaced word boundaries like "ignore[zw]all").
    cleaned = re.sub(rf"(?<=\w){_ZW_CLASS}+(?=\w)", " ", cleaned)

    # Step 1c — ZW elsewhere → remove (adjacent to spaces, punctuation, etc.)
    cleaned = _ZERO_WIDTH_RE.sub("", cleaned)

    # Step 1b — D.5: fold Mathematical Alphanumeric Symbols (U+1D400+) to
    # ASCII so bold/italic/script letters reach the Aho-Corasick automaton
    # as plain ASCII.
    cleaned = cleaned.translate(_MATH_SCRIPT_MAP)

    # Step 2 — homoglyph substitution
    cleaned = cleaned.translate(_HOMOGLYPH_TABLE)

    # Step 3 — NFKC normalization (also folds compatibility forms like
    # superscript/subscript digits and ligatures to plain ASCII).
    cleaned = unicodedata.normalize("NFKC", cleaned)

    # Step 3a' — H.10 (0.4.8): NFKC can *produce* homoglyphs the step-2 fold
    # already ran past — e.g. MICRO SIGN U+00B5 NFKC-folds to GREEK MU
    # U+03BC, which the table maps to ASCII 'u'. Without this second pass,
    # "µser" normalized to "μser" instead of "user" (found by the
    # property-based idempotency test). Re-apply the fold post-NFKC.
    cleaned = cleaned.translate(_HOMOGLYPH_TABLE)

    # Step 3b — F.3a: collapse single-char-separated obfuscation
    # ("i-g-n-o-r-e" → "ignore") for hyphen/dot/underscore/middle-dot/bullet.
    cleaned = _SEP_SINGLE_COLLAPSE_RE.sub(
        lambda m: _SEP_STRIP_RE.sub("", m.group(0)),
        cleaned,
    )
    # Step 3c — F.3b: replace inter-letter separators with a space so
    # "ignore-all-previous-instructions" matches the AC dictionary phrase
    # "ignore all previous instructions". This is *after* the single-char
    # collapse so we don't accidentally re-insert spaces into "ignore".
    cleaned = _SEP_INTERLETTER_RE.sub(" ", cleaned)

    # Step 3d-pre — H.10 (0.4.8): normalize whitespace BEFORE the
    # single-char-space collapse. Previously "i\rg\rn\ro\rr\re" survived
    # pass 1 (collapse only knew plain spaces) but collapsed on pass 2
    # after \r→space — non-idempotent, i.e. a one-pass evasion (found by
    # the property-based idempotency test).
    cleaned = re.sub(r"\s", " ", cleaned)
    cleaned = re.sub(r" {2,}", " ", cleaned)

    # Step 3d — F.5: collapse "i g n o r e" style single-char-with-space
    # obfuscation. Runs of 3+ single chars separated by exactly one space
    # collapse to the contiguous word. This fires after ZW→space contextual
    # replacement has produced single-space-separated patterns.
    cleaned = _SPACE_SINGLE_COLLAPSE_RE.sub(
        lambda m: _SPACE_STRIP_RE.sub("", m.group(0)),
        cleaned,
    )

    # Step 4 — collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    # Step 5 — lowercase
    cleaned = cleaned.lower()

    # Step 6 — W1.1 (0.5.0): final homoglyph fold AFTER lowercasing. The
    # fold table is keyed on lowercase forms, so an uppercase homoglyph
    # exposed only by case-folding slips past the earlier folds — e.g.
    # OHM SIGN U+2126 → NFKC → capital GREEK OMEGA U+03A9 → lower → 'ω',
    # which only then maps to 'w'. Re-applying here makes the function
    # idempotent (a one-pass guarantee, so a homoglyph evasion can't survive
    # a single normalization). Found by the property-based idempotency test.
    return cleaned.translate(_HOMOGLYPH_TABLE)


def has_obfuscation_chars(text: str) -> bool:
    """Return True if *text* contains zero-width / BIDI obfuscation characters.

    Used to *annotate* whether obfuscation is present — not to skip detection.
    The caller should still run all detectors on the normalized form.
    """
    return bool(_ZERO_WIDTH_RE.search(text))
