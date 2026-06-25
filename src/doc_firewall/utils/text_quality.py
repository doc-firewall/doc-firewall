"""Natural-language text-quality gate for the ML injection layers.

The BERT classifier and the bundled logistic-regression classifier are trained
on natural-language prose. When they are handed *non-prose* — PDF object syntax,
glyph-name / width tables, form-field id dumps (``Pager_0000000097 ...``), font
names + timestamps, or undecoded compressed-stream bytes — they confidently
emit an "injection" label (often score ~1.0). On a real benign-PDF corpus this
was the single dominant false-positive driver.

A genuine prompt injection is itself natural language, so refusing to classify
non-prose costs no injection recall while removing the structural-garbage FPs.
The check is script-agnostic: Chinese / Arabic / Cyrillic prose passes (those
code points are letters and carry almost no C0/C1 control characters), while
digit/symbol/slash-dominated structure does not.
"""
from __future__ import annotations

# A prose window must be at least this long to classify — shorter snippets are
# left to the regex / keyword layers, which are precise on short strings.
_MIN_PROSE_LEN = 12

# C0/C1 control characters: prose of any language has essentially none; a
# compressed/binary stream is dense with them.
_MAX_CONTROL_RATIO = 0.02
# Digits dominate width arrays, ids and timestamps ("Pager_0000000097",
# "D:20080708084438") but are sparse in prose.
_MAX_DIGIT_RATIO = 0.18
# PDF glyph-name encoding arrays look like "/space/T/L/S/comma/..." — slash-dense.
_MAX_SLASH_RATIO = 0.08
# Prose is dominated by letters (any script) and inter-word spaces. Garbled
# font-dump / base64-ish fragments carry many symbols, dropping this ratio.
# Set above the ~0.6 such fragments reach; real prose of any script (incl.
# space-free CJK, which is ~100% letters) sits far higher.
_MIN_LETTER_SPACE_RATIO = 0.72


def looks_like_prose(s: str) -> bool:
    """True when *s* reads as natural-language text worth running an ML
    injection classifier on (rather than PDF structure / binary / id dumps)."""
    s = (s or "").strip()
    n = len(s)
    if n < _MIN_PROSE_LEN:
        return False

    ctrl = letters = spaces = digits = slashes = 0
    for c in s:
        o = ord(c)
        if (o < 0x20 and c not in "\t\n\r") or 0x7F <= o <= 0x9F:
            ctrl += 1
        if c.isalpha():
            letters += 1
        elif c.isspace():
            spaces += 1
        elif c.isdigit():
            digits += 1
        elif c == "/":
            slashes += 1

    if ctrl / n > _MAX_CONTROL_RATIO:
        return False
    if digits / n > _MAX_DIGIT_RATIO:
        return False
    if slashes / n > _MAX_SLASH_RATIO:
        return False
    if (letters + spaces) / n < _MIN_LETTER_SPACE_RATIO:
        return False
    return True


__all__ = ["looks_like_prose"]
