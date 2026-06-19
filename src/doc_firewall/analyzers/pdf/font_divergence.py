"""W5 (0.5.0) — measured rendered-vs-extracted text divergence (T3).

The "font substitution" attack: a PDF font's glyphs *render* one string, but
its ``/ToUnicode`` CMap — what text extraction (and therefore an LLM/RAG
pipeline) reads — maps to a *different* string. A human reviewer approves
what renders; the scanner/LLM ingests something else (or vice-versa).

Earlier versions only emitted an INFO note that a CMap *exists* (structurally
indistinguishable from a benign subset font). This module produces a
**measured** signal instead: for each font it compares

  * the **rendered** text, implied by the glyph *names* in the font's
    ``/Encoding /Differences`` (glyph name → Unicode via the Adobe Glyph
    List), against
  * the **extracted** text, given by the ``/ToUnicode`` CMap for the same
    character codes.

When a meaningful number of codes disagree, the two strings are reconstructed
and returned as evidence. Benign fonts — where the glyph name matches the
ToUnicode mapping, or where glyph names carry no derivable Unicode — produce
no divergence, so this does not false-positive on ordinary embedded fonts.

Raw-bytes only (regex + FlateDecode); no PDF library, hard caps, never raises.
"""
from __future__ import annotations

import re
import zlib
from typing import Dict, List, Optional

from .action_resolver import _index_objects

_MAX_FONTS = 64
_MAX_CODES = 1024
_ZLIB_BUDGET = 262_144
_MIN_DIVERGENCES = 3          # ignore one-off coincidences
_MIN_DIVERGENCE_RATIO = 0.30  # of the comparable codes

_FONT_HINT_RE = re.compile(rb"/ToUnicode\b")
_TOUNICODE_REF_RE = re.compile(rb"/ToUnicode\s+(\d{1,7})\s+\d{1,5}\s+R")
_ENCODING_REF_RE = re.compile(rb"/Encoding\s+(\d{1,7})\s+\d{1,5}\s+R")
# An inline *named* base encoding (no /Differences). WinAnsi/Standard/MacRoman/
# PDFDoc all agree with ASCII over 0x20–0x7E, so for a NON-subset simple font
# code C in that range renders chr(C) — a reliable "rendered" reference.
_NAMED_ENCODING_RE = re.compile(rb"/Encoding\s*/(?:WinAnsi|Standard|MacRoman|PDFDoc)Encoding")
# Subset fonts (BaseFont tag "ABCDEF+Name") remap codes arbitrarily, so the
# ASCII-identity assumption does NOT hold — the base-encoding path skips them.
_SUBSET_BASEFONT_RE = re.compile(rb"/BaseFont\s*/[A-Z]{6}\+")
_DIFFERENCES_RE = re.compile(rb"/Differences\s*\[(.*?)\]", re.DOTALL)
_DIFF_TOKEN_RE = re.compile(rb"(\d+)|/([A-Za-z0-9_.]+)")
_BFCHAR_BLOCK_RE = re.compile(rb"beginbfchar(.*?)endbfchar", re.DOTALL)
_BFRANGE_BLOCK_RE = re.compile(rb"beginbfrange(.*?)endbfrange", re.DOTALL)
_HEX_RE = re.compile(rb"<([0-9A-Fa-f]+)>")


def _agl() -> Dict[str, int]:
    """Compact Adobe Glyph List: ASCII letters, digits, and punctuation —
    enough to reconstruct Latin injection text."""
    m: Dict[str, int] = {}
    for c in range(0x41, 0x5B):           # A-Z
        m[chr(c)] = c
    for c in range(0x61, 0x7B):           # a-z
        m[chr(c)] = c
    digits = ["zero", "one", "two", "three", "four",
              "five", "six", "seven", "eight", "nine"]
    for i, name in enumerate(digits):
        m[name] = 0x30 + i
    m.update({
        "space": 0x20, "exclam": 0x21, "quotedbl": 0x22, "numbersign": 0x23,
        "dollar": 0x24, "percent": 0x25, "ampersand": 0x26, "quotesingle": 0x27,
        "parenleft": 0x28, "parenright": 0x29, "asterisk": 0x2A, "plus": 0x2B,
        "comma": 0x2C, "hyphen": 0x2D, "period": 0x2E, "slash": 0x2F,
        "colon": 0x3A, "semicolon": 0x3B, "less": 0x3C, "equal": 0x3D,
        "greater": 0x3E, "question": 0x3F, "at": 0x40, "bracketleft": 0x5B,
        "backslash": 0x5C, "bracketright": 0x5D, "asciicircum": 0x5E,
        "underscore": 0x5F, "grave": 0x60, "braceleft": 0x7B, "bar": 0x7C,
        "braceright": 0x7D, "asciitilde": 0x7E,
    })
    return m


_AGL = _agl()


def _glyph_name_to_unicode(name: str) -> Optional[int]:
    if name in _AGL:
        return _AGL[name]
    if re.fullmatch(r"uni[0-9A-Fa-f]{4}", name):
        return int(name[3:], 16)
    if re.fullmatch(r"u[0-9A-Fa-f]{4,6}", name):
        return int(name[1:], 16)
    return None


class _Resolver:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.index = _index_objects(blob)

    def obj(self, num: int) -> Optional[bytes]:
        span = self.index.get(num)
        return self.blob[span[0]:span[1]] if span else None


def _parse_differences(enc_bytes: bytes) -> Dict[int, str]:
    """code → glyph name from an /Encoding /Differences array."""
    out: Dict[int, str] = {}
    m = _DIFFERENCES_RE.search(enc_bytes)
    if not m:
        return out
    code = 0
    for tok in _DIFF_TOKEN_RE.finditer(m.group(1)):
        if tok.group(1) is not None:
            code = int(tok.group(1))
        else:
            out[code] = tok.group(2).decode("latin-1")
            code += 1
        if len(out) >= _MAX_CODES:
            break
    return out


def _decode_utf16be(hexstr: bytes) -> str:
    try:
        return bytes.fromhex(hexstr.decode("ascii")).decode("utf-16-be", "replace")
    except Exception:
        return ""


def _parse_tounicode(stream: bytes) -> Dict[int, str]:
    """code → unicode string from a ToUnicode CMap stream."""
    out: Dict[int, str] = {}
    for block in _BFCHAR_BLOCK_RE.finditer(stream):
        hexes = _HEX_RE.findall(block.group(1))
        for i in range(0, len(hexes) - 1, 2):
            try:
                code = int(hexes[i].decode("ascii"), 16)
            except ValueError:
                continue
            out[code] = _decode_utf16be(hexes[i + 1])
            if len(out) >= _MAX_CODES:
                return out
    for block in _BFRANGE_BLOCK_RE.finditer(stream):
        hexes = _HEX_RE.findall(block.group(1))
        for i in range(0, len(hexes) - 2, 3):
            try:
                lo = int(hexes[i].decode("ascii"), 16)
                hi = int(hexes[i + 1].decode("ascii"), 16)
                base = bytes.fromhex(hexes[i + 2].decode("ascii"))
            except (ValueError, Exception):
                continue
            if hi - lo > _MAX_CODES:
                continue
            try:
                base_cp = int.from_bytes(base, "big")
            except Exception:
                continue
            for j, code in enumerate(range(lo, hi + 1)):
                cp = base_cp + j
                try:
                    out[code] = chr(cp) if cp <= 0x10FFFF else ""
                except ValueError:
                    out[code] = ""
                if len(out) >= _MAX_CODES:
                    return out
    return out


def _stream_bytes(obj: bytes) -> bytes:
    s = obj.find(b"stream")
    if s == -1:
        return b""
    ds = s + len(b"stream")
    if obj[ds:ds + 2] == b"\r\n":
        ds += 2
    elif obj[ds:ds + 1] in (b"\n", b"\r"):
        ds += 1
    e = obj.find(b"endstream", ds)
    raw = obj[ds:e if e != -1 else None][:_ZLIB_BUDGET]
    if b"/FlateDecode" in obj[:s]:
        try:
            return zlib.decompressobj().decompress(raw, _ZLIB_BUDGET)
        except zlib.error:
            return b""
    return raw


def _rendered_from_differences(enc_obj: bytes) -> Dict[int, int]:
    """code → rendered Unicode codepoint, from an /Encoding /Differences
    array (glyph name → Unicode via the AGL). Codes whose glyph name carries
    no derivable Unicode are omitted."""
    rendered: Dict[int, int] = {}
    for code, name in _parse_differences(enc_obj).items():
        cp = _glyph_name_to_unicode(name)
        if cp is not None:
            rendered[code] = cp
    return rendered


def _rendered_from_base_encoding(tounicode: Dict[int, str]) -> Dict[int, int]:
    """code → rendered codepoint for a NON-subset font with a standard named
    base encoding: over printable ASCII (0x21–0x7E) the rendered glyph for
    code C is chr(C). Restricted to codes the ToUnicode map also defines, so
    we only compare where both sides have a reference."""
    return {
        code: code
        for code in tounicode
        if 0x21 <= code <= 0x7E
    }


def _divergence_record(
    rendered: Dict[int, int], tounicode: Dict[int, str]
) -> Optional[Dict]:
    """Compare a rendered-codepoint map against the ToUnicode (extracted) map
    and return a divergence record when they disagree past the thresholds."""
    rendered_chars: List[str] = []
    extracted_chars: List[str] = []
    diverging = 0
    comparable = 0
    for code in sorted(set(rendered) & set(tounicode)):
        actual = tounicode[code]
        # Only compare single, printable extracted chars — empty / multi-char
        # ToUnicode entries (ligatures, unmapped) are not reliable evidence.
        if len(actual) != 1 or not actual.isprintable():
            continue
        expected = chr(rendered[code])
        comparable += 1
        rendered_chars.append(expected)
        extracted_chars.append(actual)
        if actual != expected:
            diverging += 1
    if (
        comparable
        and diverging >= _MIN_DIVERGENCES
        and diverging / comparable >= _MIN_DIVERGENCE_RATIO
    ):
        return {
            "rendered": "".join(rendered_chars)[:250],
            "extracted": "".join(extracted_chars)[:250],
            "diverging_codes": diverging,
            "comparable_codes": comparable,
        }
    return None


def analyze_font_divergence(blob: bytes) -> List[Dict]:
    """Return a list of per-font divergence records:
    ``{rendered, extracted, diverging_codes, comparable_codes}``. Empty when
    no font's rendered text disagrees with its extracted text. Never raises.

    Two complementary "rendered" references are compared against ``/ToUnicode``:
      * ``/Encoding /Differences`` glyph names (any font), and
      * the ASCII identity of a standard *named* base encoding, for a
        non-subset simple font with no Differences array — catching a lying
        ToUnicode that needs no Differences array to mount the attack.
    """
    out: List[Dict] = []
    try:
        if b"/ToUnicode" not in blob:
            return out
        r = _Resolver(blob)
        fonts_done = 0
        for fm in _FONT_HINT_RE.finditer(blob):
            if fonts_done >= _MAX_FONTS:
                break
            # The enclosing object body holds the font dict.
            obj_start = blob.rfind(b"obj", 0, fm.start())
            if obj_start == -1:
                continue
            obj_end = blob.find(b"endobj", fm.start())
            font_dict = blob[obj_start:obj_end if obj_end != -1 else min(len(blob), obj_start + 4096)]

            tu_m = _TOUNICODE_REF_RE.search(font_dict)
            if not tu_m:
                continue
            tu_obj = r.obj(int(tu_m.group(1)))
            if not tu_obj:
                continue
            tounicode = _parse_tounicode(_stream_bytes(tu_obj))
            if not tounicode:
                continue
            fonts_done += 1

            rendered: Dict[int, int] = {}
            # Path 1 — explicit /Encoding /Differences (indirect ref).
            enc_m = _ENCODING_REF_RE.search(font_dict)
            if enc_m:
                enc_obj = r.obj(int(enc_m.group(1)))
                if enc_obj:
                    rendered = _rendered_from_differences(enc_obj)
            # Path 2 — standard named base encoding on a NON-subset font: the
            # ToUnicode can lie without any Differences array.
            if (
                not rendered
                and _NAMED_ENCODING_RE.search(font_dict)
                and not _SUBSET_BASEFONT_RE.search(font_dict)
            ):
                rendered = _rendered_from_base_encoding(tounicode)
            if not rendered:
                continue

            record = _divergence_record(rendered, tounicode)
            if record:
                out.append(record)
        return out
    except Exception:
        return out
