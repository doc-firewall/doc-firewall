"""PDF JavaScript risk tiering (0.5.0).

The mere presence of ``/JavaScript`` / ``/JS`` is not, by itself, malicious:
every fillable government/AcroForm PDF embeds JavaScript for field calculation,
formatting and viewer checks. Flagging all of them at MEDIUM/HIGH produced a
large false-positive rate on real benign forms.

This classifier inspects *what the JavaScript actually does* — across raw bytes
and decompressed FlateDecode streams — and returns one of three tiers:

  ``dangerous``    a known code-execution / network / data-exfil / exploit API
                   is present (``app.launchURL``, ``exportDataObject``,
                   ``util.printf``, ``eval`` / ``unescape`` shellcode, the
                   classic CVE primitives). Keep flagging at HIGH.
  ``benign``       JavaScript is present and uses only recognised form /
                   viewer APIs (``AFSimple_Calculate``, ``app.viewerType``,
                   ``event.value`` …) with no dangerous API. Downgrade to INFO.
  ``unverified``   JavaScript is present but its body could not be classified
                   (obfuscated, undecodable stream). Fail-safe — keep the
                   existing MEDIUM/REVIEW verdict.

It never raises and is bounded against decompression bombs.
"""
from __future__ import annotations

import re
import zlib

from .action_resolver import (
    _index_objects,
    _read_stream_text,
    _read_string_value,
    resolve_pdf_actions,
)

# Code-execution / network / exfiltration / known-CVE JavaScript primitives.
# Substrings are matched case-insensitively. submitForm/mailDoc are deliberately
# NOT here — legitimate forms submit to a server — so they do not force HIGH.
_DANGEROUS_JS_APIS = (
    "launchurl", "geturl", "app.launch", "openurl",
    "exportdataobject", "importdataobject", "exportasfdf",
    "exportasxfdf", "createdataobject", "getdataobjectcontents",
    "util.printf", "media.newplayer", "collab.collectemailinfo",
    "collab.geticon", "spell.customdictionaryopen", "syncannotscan",
    "eval(", "unescape(", "fromcharcode", "%u9090", "%u0c0c", "\\u9090",
    "soap.connect", "net.http", "this.submitform(", "app.opendoc",
)

# Recognised benign form / viewer JavaScript markers. Presence of any of these
# (with no dangerous API) identifies legitimate AcroForm / viewer scripting.
_BENIGN_JS_MARKERS = (
    "afsimple_calculate", "afnumber_format", "afdate_format", "aftime_format",
    "afpercent_format", "afspecial_format", "afmakenumber", "afrange_validate",
    "afmergechange", "afnumber_keystroke", "afspecial_keystroke",
    "app.viewertype", "app.viewerversion", "app.viewervariation",
    "event.value", "event.target", "event.rc", "event.change",
    "this.getfield", "this.resetform", "this.calculatenow", "app.alert",
    "this.dirty", "this.numfields", "needsupdate",
)

_HAS_JS_RE = re.compile(rb"/JavaScript\b|/JS\b")
_JS_KEY_RE = re.compile(rb"/JS\b")
_JS_INDIRECT_RE = re.compile(rb"/JS\s+(\d{1,7})\s+\d+\s+R")
_MAX_JS_SITES = 300
_STREAM_RE = re.compile(rb"stream\r?\n")
_MAX_STREAMS = 400
_DECOMP_BUDGET = 4 * 1024 * 1024
_PER_STREAM_CAP = 1024 * 1024


def _flate_chunks(blob: bytes) -> list[bytes]:
    """Decompress FlateDecode streams (bounded). JavaScript action dictionaries
    are frequently stored compressed, so they are invisible to a raw-byte
    /JS scan. Never raises."""
    out: list[bytes] = []
    consumed = 0
    count = 0
    for m in _STREAM_RE.finditer(blob):
        if count >= _MAX_STREAMS or consumed >= _DECOMP_BUDGET:
            break
        count += 1
        if b"FlateDecode" not in blob[max(0, m.start() - 400): m.start()]:
            continue
        start = m.end()
        end = blob.find(b"endstream", start)
        raw = blob[start: end if end != -1 else start + _PER_STREAM_CAP][:_PER_STREAM_CAP]
        try:
            d = zlib.decompressobj().decompress(raw, _PER_STREAM_CAP)
        except Exception:
            continue
        if d:
            out.append(d)
            consumed += len(d)
    return out


def _extract_js_at(buf: bytes, pos: int, blob: bytes, index: dict) -> str | None:
    """Extract the JavaScript body for a ``/JS`` key at *pos* in *buf*. Inline
    literal/hex is read from *buf*; an indirect ``N 0 R`` is resolved against
    the main *blob* object *index*."""
    seg = buf[pos: pos + 5000]
    val = _read_string_value(seg, b"/JS")        # inline ( … ) or <hex>
    if val:
        return val
    ref = _JS_INDIRECT_RE.match(buf, pos)
    if ref:
        span = index.get(int(ref.group(1)))
        if span:
            txt, _ = _read_stream_text(blob, span)   # stream (decompressed)
            if txt:
                return txt
            sm = re.search(rb"\(((?:[^)\\]|\\.){0,8192})\)", blob[span[0]: span[1]])
            if sm:
                return sm.group(1).decode("latin-1", errors="replace")
    return None


def _gather_js(blob: bytes) -> tuple[list[str], bool]:
    """Return ``(js_bodies, js_present)``.

    Extracts JavaScript source — NOT raw binary, so font/image bytes can't
    coincidentally match a dangerous-API substring — from resolved /OpenAction &
    /AA scripts, inline/indirect ``/JS`` values, AND the same keys found inside
    decompressed FlateDecode streams. Bounded; never raises.
    """
    bodies: list[str] = []
    js_present = bool(_HAS_JS_RE.search(blob))
    try:
        for a in resolve_pdf_actions(blob):
            if a.get("action_type") == "javascript" and a.get("target"):
                bodies.append(a["target"])
    except Exception:
        pass
    try:
        index = _index_objects(blob)
    except Exception:
        index = {}

    sites = 0
    # Raw bytes first, then each decompressed FlateDecode stream.
    for buf in [blob, *_flate_chunks(blob)]:
        if buf is not blob and _HAS_JS_RE.search(buf):
            js_present = True
        for m in _JS_KEY_RE.finditer(buf):
            if sites >= _MAX_JS_SITES:
                break
            sites += 1
            body = _extract_js_at(buf, m.start(), blob, index)
            if body:
                bodies.append(body)
    return bodies, js_present


# Non-JS action tokens that make an /OpenAction or /AA trigger genuinely
# dangerous regardless of how benign the JavaScript is.
_DANGEROUS_ACTION_TOKENS = (b"/Launch", b"/EmbeddedFile", b"/Filespec", b"/GoToE")


def benign_js_only(blob: bytes) -> bool:
    """True when the document's active content is benign form/viewer JavaScript
    AND it has no dangerous non-JS action token — i.e. the /JavaScript, /JS,
    /AA and /OpenAction active-content findings can be safely demoted to INFO.
    """
    try:
        if any(t in blob for t in _DANGEROUS_ACTION_TOKENS):
            return False
        return classify_pdf_js_risk(blob) == "benign"
    except Exception:
        return False


def classify_pdf_js_risk(blob: bytes) -> str:
    """Return 'dangerous' | 'benign' | 'unverified' | 'none' for *blob*."""
    try:
        bodies, js_present = _gather_js(blob)
        if not js_present:
            return "none"
        text = "\n".join(b for b in bodies if b).lower()
        if not text.strip():
            return "unverified"   # JS present but body not extractable — fail safe
        if any(api in text for api in _DANGEROUS_JS_APIS):
            return "dangerous"
        if any(marker in text for marker in _BENIGN_JS_MARKERS):
            return "benign"
        return "unverified"
    except Exception:
        return "unverified"


__all__ = ["classify_pdf_js_risk", "benign_js_only"]
