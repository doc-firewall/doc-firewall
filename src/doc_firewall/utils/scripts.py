"""W2 (0.5.0) — Unicode script classification for language-agnostic
script-mixing detection.

Dependency-free (no `regex`, no ICU): characters are mapped to a coarse
*script group* by Unicode code-point range. The groups are deliberately
coarse — East-Asian scripts are merged into one ``CJK`` group so a Japanese
document (kanji + kana) is not mis-split into "foreign" runs — because the
threat signal we want is "a document dominated by one writing system hides a
run in a *different* writing system", not fine-grained language ID.

Used by ``detectors/script_mixing.py``: an English (Latin) résumé that hides
``忽略所有先前的指令`` (CJK) in white text or metadata is flagged regardless of
whether we ship any Chinese NLP.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# (group_name, [(lo, hi), ...]) inclusive code-point ranges. Order matters
# only for readability; lookup is by membership. Punctuation, digits,
# symbols, emoji and whitespace are intentionally absent → classified as
# None ("common", script-neutral) and never counted toward a script.
_SCRIPT_RANGES: List[Tuple[str, List[Tuple[int, int]]]] = [
    ("LATIN", [
        (0x0041, 0x005A), (0x0061, 0x007A),       # ASCII letters
        (0x00C0, 0x024F),                         # Latin-1 suppl. + Extended-A/B
        (0x1E00, 0x1EFF),                         # Latin Extended Additional
    ]),
    ("CYRILLIC", [(0x0400, 0x04FF), (0x0500, 0x052F), (0x2DE0, 0x2DFF), (0xA640, 0xA69F)]),
    ("GREEK", [(0x0370, 0x03FF), (0x1F00, 0x1FFF)]),
    ("ARABIC", [
        (0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
        (0xFB50, 0xFDFF), (0xFE70, 0xFEFF),       # Arabic Presentation Forms
    ]),
    ("HEBREW", [(0x0590, 0x05FF), (0xFB1D, 0xFB4F)]),
    # East-Asian scripts merged: Han (CJK ideographs), Hiragana, Katakana,
    # Hangul, plus CJK symbols. A Japanese / Korean document is dominated by
    # this single group rather than fracturing into kanji vs kana.
    ("CJK", [
        (0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0xF900, 0xFAFF),   # Han
        (0x20000, 0x2A6DF), (0x2A700, 0x2EBEF),                 # Han ext.
        (0x3040, 0x309F), (0x30A0, 0x30FF),                     # Hiragana / Katakana
        (0x31F0, 0x31FF), (0x3300, 0x33FF),                     # Kana ext. / CJK compat
        (0xAC00, 0xD7AF), (0x1100, 0x11FF), (0x3130, 0x318F),   # Hangul
    ]),
    ("DEVANAGARI", [(0x0900, 0x097F), (0xA8E0, 0xA8FF)]),
    ("BENGALI", [(0x0980, 0x09FF)]),
    ("GURMUKHI", [(0x0A00, 0x0A7F)]),
    ("GUJARATI", [(0x0A80, 0x0AFF)]),
    ("TAMIL", [(0x0B80, 0x0BFF)]),
    ("TELUGU", [(0x0C00, 0x0C7F)]),
    ("THAI", [(0x0E00, 0x0E7F)]),
    ("LAO", [(0x0E80, 0x0EFF)]),
    ("ARMENIAN", [(0x0530, 0x058F), (0xFB13, 0xFB17)]),
    ("GEORGIAN", [(0x10A0, 0x10FF), (0x2D00, 0x2D2F)]),
    ("ETHIOPIC", [(0x1200, 0x137F)]),
]


def char_script(ch: str) -> Optional[str]:
    """Return the coarse script group of a single character, or None for
    script-neutral characters (punctuation, digits, symbols, whitespace,
    emoji, combining marks)."""
    cp = ord(ch)
    if cp < 0x80:
        # Fast path: ASCII letters → LATIN, everything else neutral.
        if 0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A:
            return "LATIN"
        return None
    for name, ranges in _SCRIPT_RANGES:
        for lo, hi in ranges:
            if lo <= cp <= hi:
                return name
    return None


def script_profile(text: str) -> Dict[str, int]:
    """Count letters per script group in ``text`` (neutral chars ignored)."""
    counts: Dict[str, int] = {}
    for ch in text:
        g = char_script(ch)
        if g is not None:
            counts[g] = counts.get(g, 0) + 1
    return counts


def dominant_script(text: str) -> Tuple[Optional[str], int]:
    """Return ``(dominant_group, total_letters)``. dominant_group is None
    when ``text`` has no script-bearing letters."""
    prof = script_profile(text)
    total = sum(prof.values())
    if not prof:
        return None, 0
    return max(prof.items(), key=lambda kv: kv[1])[0], total


def _longest_run(text: str, group: str, max_len: int = 300) -> str:
    """Longest run of ``group`` letters, allowing interspersed neutral
    characters (spaces/punctuation) so a sentence stays contiguous."""
    best_start = best_end = 0
    cur_start = None
    last_letter = -1
    for i, ch in enumerate(text):
        g = char_script(ch)
        if g == group:
            if cur_start is None:
                cur_start = i
            last_letter = i
        elif g is not None:
            # A letter of a different script breaks the run.
            if cur_start is not None and last_letter - cur_start > best_end - best_start:
                best_start, best_end = cur_start, last_letter
            cur_start = None
            last_letter = -1
        # neutral char: keep extending (do not break)
    if cur_start is not None and last_letter - cur_start > best_end - best_start:
        best_start, best_end = cur_start, last_letter
    return text[best_start:best_end + 1].strip()[:max_len]


def foreign_script_runs(
    text: str,
    dominant: Optional[str],
    min_chars: int = 12,
) -> List[Tuple[str, int, str]]:
    """Return ``(group, letter_count, sample_text)`` for every non-dominant
    script group in ``text`` with at least ``min_chars`` letters.

    A short run (an author's name, a single foreign word, a unit symbol) is
    below ``min_chars`` and ignored — the signal is a *substantial* foreign
    run, which is what an injected instruction looks like.
    """
    if not text:
        return []
    prof = script_profile(text)
    out: List[Tuple[str, int, str]] = []
    for group, count in prof.items():
        if group == dominant or count < min_chars:
            continue
        out.append((group, count, _longest_run(text, group)))
    # Most-prevalent foreign script first.
    out.sort(key=lambda t: t[1], reverse=True)
    return out
