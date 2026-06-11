"""H.2 (0.4.8) — PDF action-target resolution.

Follows ``/OpenAction`` and ``/AA`` entries to the action they actually
execute, so findings can report *what the action does* (the JavaScript body,
the URI, the launch command) instead of just "the token /OpenAction exists".

This is a raw-bytes resolver: regex object indexing + a balanced ``<< >>``
scanner + optional FlateDecode inflation. No external PDF library, hard caps
everywhere, and it never raises — on malformed input it returns actions with
``action_type="unresolvable"`` and a human-readable ``reason``.

Action classification:

  ``javascript``   /S /JavaScript — script body extracted where possible
  ``launch``       /S /Launch — external program/file, command extracted
  ``uri``          /S /URI — target URL extracted
  ``submit_form``  /S /SubmitForm — form data posted to extracted URL
  ``goto_remote``  /S /GoToR or /GoToE — jump into another file (extracted)
  ``goto``         /S /GoTo or a bare destination array — internal page
                   navigation ("open at page N"); benign
  ``named``        /S /Named — named viewer action (/NextPage etc.)
  ``unresolvable`` target object missing / encrypted / unsupported filter
"""
from __future__ import annotations

import re
import zlib
from typing import Dict, List, Optional, Tuple

_MAX_DICT_LEN = 16_384       # balanced-scanner cap per dictionary
_MAX_ACTIONS = 50            # cap resolved actions per document
_MAX_CHAIN_DEPTH = 4         # /Next action chains
_MAX_JS_EXCERPT = 300
_ZLIB_BUDGET = 262_144       # decompressed bytes per stream
_MAX_OBJSTM = 64             # cap object streams parsed per document
_MAX_OBJSTM_OBJS = 5_000     # cap objects extracted from object streams

_OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,7})\s+(\d{1,5})\s+obj\b")
_OBJSTM_RE = re.compile(rb"/Type\s*/ObjStm\b")
_REF_RE = re.compile(rb"^(\d{1,7})\s+(\d{1,5})\s+R")
_OPENACTION_RE = re.compile(rb"/OpenAction\s*(?=(\d{1,7}\s+\d{1,5}\s+R|<<|\[))")
_AA_RE = re.compile(rb"/AA\s*(?=(<<|\d{1,7}\s+\d{1,5}\s+R))")
_ACTION_S_RE = re.compile(rb"/S\s*/([A-Za-z]+)")
_AA_TRIGGER_RE = re.compile(
    rb"/(O|C|K|F|V|Fo|Bl|U|D|E|X|WC|WS|DS|WP|DP|PV|PI|PO|PC)\s*(?=(<<|\d{1,7}\s+\d{1,5}\s+R))"
)

# Named actions a stock viewer exposes through its own UI — benign.
_BENIGN_NAMED = {"NextPage", "PrevPage", "FirstPage", "LastPage", "GoBack", "GoForward"}


def _index_objects(blob: bytes) -> Dict[int, Tuple[int, int]]:
    """Map object number → (body_start, body_end) byte offsets."""
    index: Dict[int, Tuple[int, int]] = {}
    for m in _OBJ_RE.finditer(blob):
        num = int(m.group(1))
        start = m.end()
        end = blob.find(b"endobj", start)
        if end == -1:
            end = min(len(blob), start + _MAX_DICT_LEN)
        # Last definition wins (incremental updates append redefinitions).
        index[num] = (start, end)
        if len(index) > 100_000:
            break
    return index


def _extract_dict(blob: bytes, pos: int) -> Optional[bytes]:
    """Return the balanced ``<< ... >>`` starting at/after ``pos``."""
    start = blob.find(b"<<", pos)
    if start == -1 or start - pos > 64:
        return None
    depth = 0
    i = start
    end_cap = min(len(blob), start + _MAX_DICT_LEN)
    while i < end_cap - 1:
        pair = blob[i : i + 2]
        if pair == b"<<":
            depth += 1
            i += 2
            continue
        if pair == b">>":
            depth -= 1
            i += 2
            if depth == 0:
                return blob[start:i]
            continue
        i += 1
    return None


def _extract_array(blob: bytes, pos: int) -> Optional[bytes]:
    start = blob.find(b"[", pos)
    if start == -1 or start - pos > 64:
        return None
    end = blob.find(b"]", start)
    if end == -1 or end - start > _MAX_DICT_LEN:
        return None
    return blob[start : end + 1]


def _decode_pdf_string(raw: bytes) -> str:
    """Decode a PDF literal string body (without the surrounding parens)."""
    out = bytearray()
    i = 0
    while i < len(raw) and len(out) < 2 * _MAX_JS_EXCERPT:
        b = raw[i : i + 1]
        if b == b"\\" and i + 1 < len(raw):
            nxt = raw[i + 1 : i + 2]
            mapping = {
                b"n": b"\n", b"r": b"\r", b"t": b"\t",
                b"(": b"(", b")": b")", b"\\": b"\\",
            }
            out += mapping.get(nxt, nxt)
            i += 2
            continue
        out += b
        i += 1
    data = bytes(out)
    if data[:2] == b"\xfe\xff":
        try:
            return data[2:].decode("utf-16-be", errors="replace")
        except Exception:
            pass
    return data.decode("latin-1", errors="replace")


def _read_string_value(body: bytes, key: bytes) -> Optional[str]:
    """Extract ``/Key (literal)`` or ``/Key <hex>`` from a dict body."""
    m = re.search(re.escape(key) + rb"\s*\(", body)
    if m:
        # Walk to the matching close-paren, honouring backslash escapes.
        i = m.end()
        depth = 1
        start = i
        while i < len(body) and i - start < 4096:
            c = body[i : i + 1]
            if c == b"\\":
                i += 2
                continue
            if c == b"(":
                depth += 1
            elif c == b")":
                depth -= 1
                if depth == 0:
                    return _decode_pdf_string(body[start:i])
            i += 1
        return _decode_pdf_string(body[start : start + 4096])
    m = re.search(re.escape(key) + rb"\s*<([0-9A-Fa-f\s]{2,4096})>", body)
    if m:
        try:
            return _decode_pdf_string(bytes.fromhex(m.group(1).decode("ascii").replace(" ", "").replace("\n", "").replace("\r", "")))
        except Exception:
            return None
    return None


def _read_stream_text(blob: bytes, obj_span: Tuple[int, int]) -> Tuple[Optional[str], Optional[str]]:
    """Extract (text, fail_reason) from a stream object body."""
    start, end = obj_span
    body = blob[start:end]
    s = body.find(b"stream")
    if s == -1:
        return None, "referenced object holds no string or stream data"
    data_start = s + len(b"stream")
    if body[data_start : data_start + 2] == b"\r\n":
        data_start += 2
    elif body[data_start : data_start + 1] == b"\n":
        data_start += 1
    e = body.find(b"endstream", data_start)
    raw = body[data_start : e if e != -1 else None][: _ZLIB_BUDGET]
    header = body[:s]
    if b"/FlateDecode" in header:
        try:
            raw = zlib.decompressobj().decompress(raw, _ZLIB_BUDGET)
        except zlib.error:
            return None, (
                "script is stored in a FlateDecode stream that failed to "
                "decompress (corrupt, encrypted, or multi-filter)"
            )
    elif re.search(rb"/Filter\s*[/\[]", header):
        filt = re.search(rb"/Filter\s*(/[A-Za-z0-9]+|\[[^\]]{0,200}\])", header)
        return None, (
            "script is stored in a stream with an unsupported filter "
            f"({(filt.group(1).decode('latin-1') if filt else 'unknown')})"
        )
    text = raw.decode("latin-1", errors="replace").strip()
    return (text or None), (None if text else "stream decoded to empty content")


def _extract_objstm_objects(
    blob: bytes, index: Dict[int, Tuple[int, int]]
) -> Dict[int, bytes]:
    """H.12 (0.4.8): extract objects packed inside ``/ObjStm`` compressed
    object streams (PDF 1.5+). An action dictionary hidden in an object
    stream is invisible to a raw-byte token scan — this surfaces it.

    Returns objnum → object-body bytes. Never raises.
    """
    out: Dict[int, bytes] = {}
    streams_done = 0
    for sm in _OBJSTM_RE.finditer(blob):
        if streams_done >= _MAX_OBJSTM or len(out) >= _MAX_OBJSTM_OBJS:
            break
        # Find the enclosing object body: walk back to the nearest "obj".
        obj_start = blob.rfind(b"obj", 0, sm.start())
        if obj_start == -1:
            continue
        end = blob.find(b"endobj", sm.start())
        body = blob[obj_start: end if end != -1 else min(len(blob), obj_start + _ZLIB_BUDGET)]

        n_m = re.search(rb"/N\s+(\d{1,6})", body)
        first_m = re.search(rb"/First\s+(\d{1,7})", body)
        if not n_m or not first_m:
            continue
        n = int(n_m.group(1))
        first = int(first_m.group(1))
        if n <= 0 or n > _MAX_OBJSTM_OBJS:
            continue

        s = body.find(b"stream")
        if s == -1:
            continue
        ds = s + len(b"stream")
        if body[ds: ds + 2] == b"\r\n":
            ds += 2
        elif body[ds: ds + 1] in (b"\n", b"\r"):
            ds += 1
        e = body.find(b"endstream", ds)
        raw = body[ds: e if e != -1 else None][:_ZLIB_BUDGET]
        if b"/FlateDecode" in body[:s]:
            try:
                raw = zlib.decompressobj().decompress(raw, _ZLIB_BUDGET)
            except zlib.error:
                continue
        if first > len(raw):
            continue

        # Header: N pairs of "objnum offset" (offset relative to /First).
        header = raw[:first]
        nums = re.findall(rb"(\d{1,7})\s+(\d{1,7})", header)[:n]
        for i, (onum, off) in enumerate(nums):
            try:
                start = first + int(off)
                stop = (
                    first + int(nums[i + 1][1]) if i + 1 < len(nums) else len(raw)
                )
            except (ValueError, IndexError):
                continue
            if 0 <= start < stop <= len(raw):
                out.setdefault(int(onum), raw[start:stop].strip())
            if len(out) >= _MAX_OBJSTM_OBJS:
                break
        streams_done += 1
    return out


class _Resolver:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.index = _index_objects(blob)
        self.objstm_objects = _extract_objstm_objects(blob, self.index)
        self.encrypted = b"/Encrypt" in blob

    def object_body(self, num: int) -> Optional[bytes]:
        span = self.index.get(num)
        if span is not None:
            return self.blob[span[0] : span[1]]
        # Fall back to objects unpacked from /ObjStm compressed streams.
        return self.objstm_objects.get(num)

    def _resolve_value(self, body: bytes, pos: int) -> Tuple[Optional[bytes], Optional[int]]:
        """At ``pos`` in ``body``, return (dict_or_array_bytes, obj_num)."""
        tail = body[pos : pos + 64].lstrip()
        ref = _REF_RE.match(tail)
        if ref:
            num = int(ref.group(1))
            obj = self.object_body(num)
            if obj is None:
                return None, num
            stripped = obj.lstrip()
            if stripped.startswith(b"["):
                d = _extract_array(obj, 0)
            else:
                d = _extract_dict(obj, 0) or _extract_array(obj, 0)
            return (d if d is not None else obj[:_MAX_DICT_LEN]), num
        # Inline value — dispatch on what actually follows, otherwise the
        # dict scanner can skip past an array and grab an unrelated dict.
        if tail.startswith(b"<<"):
            return _extract_dict(body, pos), None
        if tail.startswith(b"["):
            return _extract_array(body, pos), None
        return None, None

    def classify(self, action_body: Optional[bytes], obj_num: Optional[int],
                 trigger: str, depth: int = 0) -> List[Dict]:
        out: List[Dict] = []
        entry: Dict = {"trigger": trigger, "object": obj_num,
                       "action_type": "unresolvable", "target": None, "reason": None}
        if action_body is None:
            entry["reason"] = (
                "the action's target object could not be located in the file"
                + (" (document is encrypted)" if self.encrypted else
                   " (it may sit inside a compressed object stream)")
            )
            return [entry]

        if action_body.lstrip().startswith(b"["):
            entry["action_type"] = "goto"
            entry["target"] = action_body[:120].decode("latin-1", errors="replace")
            return [entry]

        s_match = _ACTION_S_RE.search(action_body)
        s_type = s_match.group(1).decode("latin-1") if s_match else None

        if s_type == "JavaScript":
            entry["action_type"] = "javascript"
            js = _read_string_value(action_body, b"/JS")
            if js is None:
                m = re.search(rb"/JS\s+(\d{1,7})\s+\d{1,5}\s+R", action_body)
                if m:
                    num = int(m.group(1))
                    span = self.index.get(num)
                    if span is None:
                        entry["reason"] = (
                            f"the /JS script lives in object {num}, which could "
                            "not be located"
                            + (" (document is encrypted)" if self.encrypted else "")
                        )
                    else:
                        js, fail = _read_stream_text(self.blob, span)
                        if js is None:
                            entry["reason"] = fail
                else:
                    entry["reason"] = "the action carries no /JS entry"
            if js:
                entry["target"] = js[:_MAX_JS_EXCERPT]
                entry["reason"] = None
        elif s_type == "URI":
            entry["action_type"] = "uri"
            entry["target"] = _read_string_value(action_body, b"/URI")
            if entry["target"] is None:
                entry["reason"] = "the /URI target string could not be decoded"
        elif s_type == "Launch":
            entry["action_type"] = "launch"
            target = (
                _read_string_value(action_body, b"/F")
                or _read_string_value(action_body, b"/Win")
                or _read_string_value(action_body, b"/Unix")
                or _read_string_value(action_body, b"/Mac")
            )
            entry["target"] = target
            if target is None:
                entry["reason"] = "the launch target could not be decoded"
        elif s_type == "SubmitForm":
            entry["action_type"] = "submit_form"
            entry["target"] = _read_string_value(action_body, b"/F")
        elif s_type in ("GoToR", "GoToE"):
            entry["action_type"] = "goto_remote"
            entry["target"] = _read_string_value(action_body, b"/F")
        elif s_type == "GoTo":
            entry["action_type"] = "goto"
            d = re.search(rb"/D\s*(\[[^\]]{0,200}\]|\([^)]{0,200}\))", action_body)
            entry["target"] = (
                d.group(1).decode("latin-1", errors="replace") if d else "internal destination"
            )
        elif s_type == "Named":
            entry["action_type"] = "named"
            n = re.search(rb"/N\s*/([A-Za-z0-9]+)", action_body)
            entry["target"] = n.group(1).decode("latin-1") if n else None
        elif s_type is None and (b"/D" in action_body or b"/Fit" in action_body):
            entry["action_type"] = "goto"
            entry["target"] = "internal destination"
        else:
            entry["action_type"] = s_type.lower() if s_type else "unresolvable"
            if s_type is None:
                entry["reason"] = "the action dictionary has no /S action type"
        out.append(entry)

        # Follow /Next chains (attackers hide payloads behind a benign hop).
        if depth < _MAX_CHAIN_DEPTH:
            m = re.search(rb"/Next\s*(?=(\d{1,7}\s+\d{1,5}\s+R|<<))", action_body)
            if m:
                nxt, nxt_num = self._resolve_value(action_body, m.end())
                out.extend(self.classify(nxt, nxt_num, trigger + "/Next", depth + 1))
        return out


def is_benign_action(action: Dict) -> bool:
    """Internal navigation and stock viewer commands are benign."""
    at = action.get("action_type")
    if at == "goto":
        return True
    if at == "named":
        return action.get("target") in _BENIGN_NAMED
    return False


def summarize_actions(actions: List[Dict]) -> Dict:
    """Build evidence fields from resolved actions for a Finding.

    Returns a dict with:
      ``resolved_actions``  compact per-action list (always present)
      ``malicious_text``    "trigger → type: target" for the first
                            non-benign action with an extracted target
      ``evidence_unavailable_reason``  set when no target could be
                            extracted for any non-benign action
      ``all_benign``        True when every action is internal navigation
    """
    ev: Dict = {
        "resolved_actions": [
            {k: a.get(k) for k in ("trigger", "action_type", "target", "reason")
             if a.get(k) is not None}
            for a in actions
        ],
        "all_benign": bool(actions) and all(is_benign_action(a) for a in actions),
    }
    reasons: List[str] = []
    for a in actions:
        if is_benign_action(a):
            continue
        if a.get("target"):
            ev["malicious_text"] = (
                f"{a['trigger']} → {a['action_type']}: {a['target']}"[:300]
            )
            break
        if a.get("reason"):
            reasons.append(f"{a['trigger']} ({a['action_type']}): {a['reason']}")
    if "malicious_text" not in ev and reasons:
        ev["evidence_unavailable_reason"] = "; ".join(reasons[:3])[:400]
    return ev


def resolve_pdf_actions(blob: bytes) -> List[Dict]:
    """Resolve every /OpenAction and /AA trigger in ``blob``.

    Returns a list of dicts: ``{trigger, object, action_type, target, reason}``.
    Never raises.
    """
    try:
        resolver = _Resolver(blob)
        actions: List[Dict] = []

        # Scan the raw bytes AND every object unpacked from /ObjStm streams —
        # an /OpenAction in a compressed catalog never appears in raw bytes.
        scan_buffers = [blob]
        scan_buffers.extend(resolver.objstm_objects.values())

        for buf in scan_buffers:
            for m in _OPENACTION_RE.finditer(buf):
                body, num = resolver._resolve_value(buf, m.end())
                actions.extend(resolver.classify(body, num, "OpenAction"))
                if len(actions) >= _MAX_ACTIONS:
                    return actions[:_MAX_ACTIONS]

            for m in _AA_RE.finditer(buf):
                aa_body, aa_num = resolver._resolve_value(buf, m.end())
                if aa_body is None:
                    actions.append({
                        "trigger": "AA", "object": aa_num,
                        "action_type": "unresolvable", "target": None,
                        "reason": "the /AA dictionary could not be located",
                    })
                    continue
                for t in _AA_TRIGGER_RE.finditer(aa_body):
                    trig = "AA:/" + t.group(1).decode("latin-1")
                    body, num = resolver._resolve_value(aa_body, t.end())
                    actions.extend(resolver.classify(body, num, trig))
                    if len(actions) >= _MAX_ACTIONS:
                        return actions[:_MAX_ACTIONS]
        return actions
    except Exception:
        return []
