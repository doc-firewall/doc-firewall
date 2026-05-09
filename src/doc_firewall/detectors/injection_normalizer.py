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
    # Cyrillic
    ord("а"): "a",  ord("е"): "e",  ord("о"): "o",  ord("р"): "p",
    ord("с"): "c",  ord("х"): "x",  ord("у"): "y",  ord("і"): "i",
    ord("ё"): "e",  ord("ѕ"): "s",  ord("ј"): "j",  ord("ԁ"): "d",
    # Greek
    ord("α"): "a",  ord("β"): "b",  ord("γ"): "y",  ord("ε"): "e",
    ord("ζ"): "z",  ord("η"): "n",  ord("ι"): "i",  ord("κ"): "k",
    ord("μ"): "u",  ord("ν"): "v",  ord("ο"): "o",  ord("ρ"): "p",
    ord("τ"): "t",  ord("υ"): "u",  ord("χ"): "x",
    # Fullwidth ASCII (！ … ～)
    **{cp: chr(cp - 0xFEE0) for cp in range(0xFF01, 0xFF5F)},
    # Latin look-alikes
    ord("ı"): "i",  ord("ℓ"): "l",  ord("ℐ"): "i",  ord("Ι"): "i",
    ord("Ο"): "o",  ord("Α"): "a",  ord("Β"): "b",  ord("Ε"): "e",
    ord("Ζ"): "z",  ord("Η"): "h",  ord("Ι"): "i",  ord("Κ"): "k",
    ord("Μ"): "m",  ord("Ν"): "n",  ord("Ο"): "o",  ord("Ρ"): "p",
    ord("Τ"): "t",  ord("Υ"): "y",  ord("Χ"): "x",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPH_MAP)

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
    cleaned = _ZERO_WIDTH_RE.sub(" ", text)

    # Step 2 — homoglyph substitution
    cleaned = cleaned.translate(_HOMOGLYPH_TABLE)

    # Step 3 — NFC normalization (compose canonical equivalents)
    cleaned = unicodedata.normalize("NFC", cleaned)

    # Step 4 — collapse whitespace
    cleaned = re.sub(r"[\n\r\t]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    # Step 5 — lowercase
    return cleaned.lower()


def has_obfuscation_chars(text: str) -> bool:
    """Return True if *text* contains zero-width / BIDI obfuscation characters.

    Used to *annotate* whether obfuscation is present — not to skip detection.
    The caller should still run all detectors on the normalized form.
    """
    return bool(_ZERO_WIDTH_RE.search(text))
