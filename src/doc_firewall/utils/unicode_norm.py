from __future__ import annotations
import unicodedata
from dataclasses import dataclass

_STEALTH_CHARS = [
    "​", "‌", "‍", "﻿",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
]
_STEALTH_SET = set(_STEALTH_CHARS)

# B.1: Tag characters (U+E0000–U+E007F) encode invisible ASCII-lookalike text
# used in prompt injection attacks.  Variation selectors (U+FE00–U+FE0F and
# the supplement U+E0100–U+E01EF) silently modify glyph rendering while the
# base codepoint is still extracted by parsers — another injection carrier.
_TAG_RANGE = range(0xE0000, 0xE0080)
_VS1_RANGE = range(0xFE00, 0xFE10)
_VS2_RANGE = range(0xE0100, 0xE01F0)

_STRIP_TABLE = str.maketrans(
    "", "",
    "".join(chr(c) for c in _TAG_RANGE)
    + "".join(chr(c) for c in _VS1_RANGE)
    + "".join(chr(c) for c in _VS2_RANGE),
)
_STRIP_SET: set[int] = set(_TAG_RANGE) | set(_VS1_RANGE) | set(_VS2_RANGE)

# D.5: Mathematical Alphanumeric Symbols block (U+1D400–U+1D7FF) lets
# attackers spell ASCII words in italic / bold / fraktur / double-struck /
# script / monospace so the result looks like text but does not match an ASCII
# regex or Aho-Corasick phrase. NFKC folds *most* of this block to ASCII, but
# the script/double-struck/fraktur sub-blocks contain characters that are
# unaffected by NFKC. We fold them explicitly.
def _build_math_script_table() -> dict[int, int]:
    table: dict[int, int] = {}
    # Math letters live in 13 sub-blocks of 26 + 26 letters each, starting at
    # different offsets.  Each sub-block is laid out A..Z then a..z (with a
    # handful of "reserved" holes filled from the Letterlike Symbols block).
    # We only need the mapping; the holes are handled below.
    sub_block_starts = [
        0x1D400,  # Bold
        0x1D434,  # Italic
        0x1D468,  # Bold Italic
        0x1D49C,  # Script
        0x1D4D0,  # Bold Script
        0x1D504,  # Fraktur
        0x1D538,  # Double-struck
        0x1D56C,  # Bold Fraktur
        0x1D5A0,  # Sans-serif
        0x1D5D4,  # Sans-serif Bold
        0x1D608,  # Sans-serif Italic
        0x1D63C,  # Sans-serif Bold Italic
        0x1D670,  # Monospace
    ]
    for start in sub_block_starts:
        for i in range(26):
            table[start + i] = ord("A") + i           # uppercase
            table[start + 26 + i] = ord("a") + i      # lowercase

    # Holes from Letterlike Symbols already covered by NFKC — but a few common
    # Letterlike characters are NOT NFKC-folded (e.g. U+2110 ℐ, U+2112 ℒ).
    extras = {
        0x2110: ord("I"),  # ℐ Script Capital I
        0x2112: ord("L"),  # ℒ Script Capital L
        0x2113: ord("l"),  # ℓ Script Small L
        0x211B: ord("R"),  # ℛ Script Capital R
        0x212C: ord("B"),  # ℬ Script Capital B
        0x212F: ord("e"),  # ℯ Script Small E
        0x2130: ord("E"),  # ℰ Script Capital E
        0x2131: ord("F"),  # ℱ Script Capital F
        0x2133: ord("M"),  # ℳ Script Capital M
        0x2134: ord("o"),  # ℴ Script Small O
        # Math digits — NFKC folds these but we add them for robustness.
        **{0x1D7CE + i: ord("0") + i for i in range(10)},   # Bold digits
        **{0x1D7E2 + i: ord("0") + i for i in range(10)},   # Double-struck
        **{0x1D7EC + i: ord("0") + i for i in range(10)},   # Sans-serif
        **{0x1D7F6 + i: ord("0") + i for i in range(10)},   # Monospace
    }
    table.update(extras)
    return table


_MATH_SCRIPT_MAP: dict[int, int] = _build_math_script_table()


@dataclass
class NormalizationStats:
    """Per-document tally of how aggressively text was normalized.

    Used by TextObfuscationDetector (D.6) so the *ratio* of stripped /
    folded characters is itself a T3 signal — even when the cleaned phrase
    happens not to match an injection list.
    """
    original_len: int = 0
    cleaned_len: int = 0
    stealth_count: int = 0      # zero-width / BIDI controls removed
    tag_strip_count: int = 0    # U+E0000+ tag chars + variation selectors
    math_script_count: int = 0  # U+1D400+ math alphanumeric folded to ASCII

    @property
    def stealth_ratio(self) -> float:
        return self.stealth_count / self.original_len if self.original_len else 0.0

    @property
    def tag_strip_ratio(self) -> float:
        return self.tag_strip_count / self.original_len if self.original_len else 0.0

    @property
    def math_script_ratio(self) -> float:
        return self.math_script_count / self.original_len if self.original_len else 0.0


def normalize_text(s: str) -> str:
    """Cheap normalization path used by detectors that don't need stats."""
    if not s:
        return s
    # Fold math/script alphanumerics → ASCII before NFKC so downstream
    # phrase matchers see plain letters.
    s = s.translate(_MATH_SCRIPT_MAP)
    s = unicodedata.normalize("NFKC", s)
    for ch in _STEALTH_CHARS:
        if ch in s:
            s = s.replace(ch, "")
    return s.translate(_STRIP_TABLE)


def normalize_text_with_stats(s: str) -> tuple[str, NormalizationStats]:
    """Normalize and report how many characters were stripped/folded.

    The caller can read `stats.tag_strip_ratio` etc. to fire a T3 signal even
    when the cleaned text doesn't match an injection list.
    """
    stats = NormalizationStats(original_len=len(s))
    if not s:
        return s, stats

    # Tally before mutation
    for cp in map(ord, s):
        if cp in _STRIP_SET:
            stats.tag_strip_count += 1
        elif 0x1D400 <= cp <= 0x1D7FF or cp in _MATH_SCRIPT_MAP:
            stats.math_script_count += 1

    # Apply transformations in order (same as `normalize_text`)
    out = s.translate(_MATH_SCRIPT_MAP)
    out = unicodedata.normalize("NFKC", out)
    stealth_before = sum(1 for ch in out if ch in _STEALTH_SET)
    stats.stealth_count = stealth_before
    for ch in _STEALTH_CHARS:
        if ch in out:
            out = out.replace(ch, "")
    out = out.translate(_STRIP_TABLE)

    stats.cleaned_len = len(out)
    return out, stats
