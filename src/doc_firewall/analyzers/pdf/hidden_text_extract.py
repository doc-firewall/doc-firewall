"""W4.1 (0.5.0) — extract text from PDF objects the renderer doesn't show.

Docling (the deep-scan PDF parser) extracts *rendered page* text. Injection
text can hide where rendering never looks — annotation ``/Contents``, form
field values ``/V``, outline ``/Title`` entries — and, worse, in objects
packed inside a compressed ``/ObjStm`` object stream so a raw-byte scan
misses them too (PDF 1.5+). 0.4.8 added ``/ObjStm`` parsing for *actions*;
this reuses that machinery to surface concealed *text* into the detector
pipeline (T3 obfuscation / T4 prompt injection, incl. the multilingual and
script-mixing layers).

Page *content streams* are not in ``/ObjStm`` (streams can't be packed into
an object stream), so this targets the dictionary surfaces that legitimately
carry strings the user never sees rendered — keeping false positives low.
"""
from __future__ import annotations

import re
from typing import List

from .action_resolver import (
    _decode_pdf_string,
    _extract_objstm_objects,
    _index_objects,
)

_MAX_STRINGS = 200          # cap extracted strings per document
_MAX_TOTAL_CHARS = 20_000   # cap total extracted text
_MIN_LEN = 4                # ignore trivial strings

# High-signal string keys whose values are user-invisible at render time.
_KEYED_STRING_RE = re.compile(
    rb"/(?:Contents|V|Title|TU|T|Subj|RC|Alt|ActualText)\s*\("
)
# A bare literal string `( ... )` (used inside decompressed ObjStm bodies).
_LITERAL_OPEN_RE = re.compile(rb"\(")


def _read_literal(blob: bytes, open_paren: int) -> tuple[str, int]:
    """Decode the PDF literal string starting at ``open_paren`` (index of
    '('). Returns (decoded, index_after_close)."""
    i = open_paren + 1
    depth = 1
    start = i
    n = len(blob)
    while i < n and i - start < 8192:
        c = blob[i : i + 1]
        if c == b"\\":
            i += 2
            continue
        if c == b"(":
            depth += 1
        elif c == b")":
            depth -= 1
            if depth == 0:
                return _decode_pdf_string(blob[start:i]), i + 1
        i += 1
    return _decode_pdf_string(blob[start:i]), i


def _harvest(buf: bytes, keyed_only: bool, out: List[str], seen: set) -> None:
    total = sum(len(s) for s in out)
    if keyed_only:
        for m in _KEYED_STRING_RE.finditer(buf):
            if len(out) >= _MAX_STRINGS or total >= _MAX_TOTAL_CHARS:
                return
            s, _ = _read_literal(buf, buf.index(b"(", m.start()))
            s = s.strip()
            if len(s) >= _MIN_LEN and s not in seen:
                seen.add(s)
                out.append(s)
                total += len(s)
    else:
        for m in _LITERAL_OPEN_RE.finditer(buf):
            if len(out) >= _MAX_STRINGS or total >= _MAX_TOTAL_CHARS:
                return
            s, _ = _read_literal(buf, m.start())
            s = s.strip()
            # Require some letters so we don't harvest binary noise.
            if len(s) >= _MIN_LEN and s not in seen and any(c.isalpha() for c in s):
                seen.add(s)
                out.append(s)
                total += len(s)


def extract_hidden_pdf_text(blob: bytes) -> List[str]:
    """Return text strings from non-rendered PDF surfaces, including objects
    unpacked from ``/ObjStm`` compressed streams. Never raises."""
    out: List[str] = []
    seen: set = set()
    try:
        # 1. Keyed invisible strings in the raw bytes (uncompressed objects).
        _harvest(blob, keyed_only=True, out=out, seen=seen)

        # 2. Objects unpacked from compressed object streams — harvest both
        # keyed strings and bare literals (annotation/outline dicts packed
        # here are entirely invisible to a raw scan).
        index = _index_objects(blob)
        objstm = _extract_objstm_objects(blob, index)
        for body in objstm.values():
            if len(out) >= _MAX_STRINGS:
                break
            _harvest(body, keyed_only=False, out=out, seen=seen)
    except Exception:
        return out
    return out
