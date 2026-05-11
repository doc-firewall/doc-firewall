import unicodedata

_STEALTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\ufeff",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
]

# B.1: Tag characters (U+E0000\u2013U+E007F) encode invisible ASCII-lookalike text
# used in prompt injection attacks.  Variation selectors (U+FE00\u2013U+FE0F and
# the supplement U+E0100\u2013U+E01EF) silently modify glyph rendering while the
# base codepoint is still extracted by parsers \u2014 another injection carrier.
_STRIP_TABLE = str.maketrans(
    "", "",
    "".join(chr(c) for c in range(0xE0000, 0xE0080))   # Tag characters
    + "".join(chr(c) for c in range(0xFE00, 0xFE10))    # Variation selectors VS-1..16
    + "".join(chr(c) for c in range(0xE0100, 0xE01F0))  # VS supplement VS-17..VS-256
)


def normalize_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    for ch in _STEALTH_CHARS:
        s = s.replace(ch, "")
    return s.translate(_STRIP_TABLE)
