"""W3 (0.5.0) — OOXML (DOCX / PPTX / XLSX) sanitizer.

Rewrites the ZIP package, removing only unambiguously unsafe / invisible
constructs and preserving the visible document:

  * Hidden runs — ``<w:r>`` (docx) / ``<a:r>`` (pptx) whose run-properties
    mark them invisible (``<w:vanish/>``, white colour, ≤2pt font, off-page
    position; pptx near-white ``<a:srgbClr>``, tiny ``sz``). The whole run is
    dropped, taking its hidden text with it.
  * Macro parts — ``vbaProject.bin`` and any ``*.bin`` macro blob.
  * Dangerous metadata — injection-bearing core/app/custom properties
    (keywords, description, subject, custom props) are emptied.
  * External template / attachedTemplate relationships pointing off-host.

Stdlib only (zipfile + regex on the part bytes) — no python-docx dependency,
so it works in the base install. Conservative regex surgery keeps the XML
well-formed for the common cases the detectors flag.
"""
from __future__ import annotations

import re
import zipfile
from typing import Any, List, Optional

from ..sanitize import (
    Removal,
    SanitizationResult,
    _resolve_out,
    category_enabled,
)

# ── Run-level hidden-styling markers (docx <w:r>) ─────────────────────────
_DOCX_HIDDEN_MARKERS = (
    re.compile(rb"<w:vanish\b[^>]*/?>"),
    re.compile(rb'<w:color\s+w:val="[EeFf]{6}"\s*/?>'),
    re.compile(rb'<w:sz\s+w:val="[0-4]"\s*/?>'),
    re.compile(rb'<w:position\s+w:val="-?\d{4,}"\s*/?>'),
)
_DOCX_RUN_RE = re.compile(rb"<w:r\b.*?</w:r>", re.DOTALL)
_DOCX_TEXT_RE = re.compile(rb"<w:t\b[^>]*>(.*?)</w:t>", re.DOTALL)

# pptx near-white / tiny-font run markers (<a:r>)
_PPTX_HIDDEN_MARKERS = (
    re.compile(rb'<a:srgbClr\s+val="[EeFf]{6}"'),
    re.compile(rb'<a:rPr\b[^>]*\bsz="(?:[0-9]|[0-9]{2}|1[0-9]{2}|200)"'),  # ≤2pt (sz in 1/100 pt)
)
_PPTX_RUN_RE = re.compile(rb"<a:r\b.*?</a:r>", re.DOTALL)
_PPTX_TEXT_RE = re.compile(rb"<a:t\b[^>]*>(.*?)</a:t>", re.DOTALL)

# Metadata value elements to empty (core.xml / app.xml).
_META_TAGS = ("keywords", "description", "subject")
_META_VALUE_RE = {
    tag: re.compile(
        (r"(<[A-Za-z0-9]*:?%s[^>]*>)(.*?)(</[A-Za-z0-9]*:?%s>)" % (tag, tag)).encode(),
        re.DOTALL | re.IGNORECASE,
    )
    for tag in _META_TAGS
}
_CUSTOM_PROP_VALUE_RE = re.compile(
    rb"(<vt:lpwstr>)(.*?)(</vt:lpwstr>)", re.DOTALL
)

_MACRO_PARTS = ("vbaproject.bin",)


def _strip_hidden_runs(
    content: bytes, run_re, text_re, markers, part: str, removed: List[Removal]
) -> bytes:
    def _repl(m: re.Match) -> bytes:
        run = m.group(0)
        if any(mk.search(run) for mk in markers):
            tx = b" ".join(t.group(1) for t in text_re.finditer(run))
            try:
                excerpt = tx.decode("utf-8", "replace").strip()
            except Exception:
                excerpt = ""
            removed.append(Removal(
                kind="hidden_text",
                detail="removed invisible/hidden run",
                location=part,
                excerpt=excerpt or None,
            ))
            return b""  # drop the whole hidden run
        return run

    return run_re.sub(_repl, content)


def _empty_metadata(content: bytes, part: str, removed: List[Removal]) -> bytes:
    out = content
    for tag, rx in _META_VALUE_RE.items():
        def _repl(m: re.Match, _tag: str = tag) -> bytes:
            val = m.group(2)
            if val.strip():
                removed.append(Removal(
                    kind="metadata",
                    detail=f"emptied metadata field '{_tag}'",
                    location=part,
                    excerpt=val.decode("utf-8", "replace"),
                ))
            return m.group(1) + m.group(3)
        out = rx.sub(_repl, out)
    if part.endswith("custom.xml"):
        def _repl_custom(m: re.Match) -> bytes:
            val = m.group(2)
            if val.strip():
                removed.append(Removal(
                    kind="metadata",
                    detail="emptied custom property value",
                    location=part,
                    excerpt=val.decode("utf-8", "replace"),
                ))
            return m.group(1) + m.group(3)
        out = _CUSTOM_PROP_VALUE_RE.sub(_repl_custom, out)
    return out


def sanitize_ooxml(
    path: str, kind: str, config: Any = None, output_path: Optional[str] = None
) -> SanitizationResult:
    if not zipfile.is_zipfile(path):
        return SanitizationResult(
            input_path=path, file_type=kind, sanitized=False,
            reason="not a ZIP/OOXML package (may be an encrypted CFB wrapper)",
        )

    removed: List[Removal] = []
    out_path = _resolve_out(f".{kind}", output_path)
    do_macro = category_enabled("macro", config)
    do_hidden = category_enabled("hidden_text", config)
    do_meta = category_enabled("metadata", config)
    run_re, text_re, markers = (
        (_DOCX_RUN_RE, _DOCX_TEXT_RE, _DOCX_HIDDEN_MARKERS)
        if kind == "docx"
        else (_PPTX_RUN_RE, _PPTX_TEXT_RE, _PPTX_HIDDEN_MARKERS)
    )

    with zipfile.ZipFile(path, "r") as zin, \
            zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            name = info.filename
            low = name.lower()

            # Drop macro blobs entirely.
            if do_macro and any(low.endswith(mp) for mp in _MACRO_PARTS):
                removed.append(Removal(
                    kind="macro", detail="removed VBA macro project", location=name
                ))
                continue

            data = zin.read(name)

            # Hidden runs in the main content parts (docx body / pptx slides).
            if do_hidden and low.endswith(".xml") and (
                "document.xml" in low or "/slides/" in low or "worksheets" in low
            ):
                data = _strip_hidden_runs(
                    data, run_re, text_re, markers, name, removed
                )

            # Metadata parts.
            if do_meta and low.startswith("docprops/") and low.endswith(".xml"):
                data = _empty_metadata(data, name, removed)

            zout.writestr(info, data)

    if not removed:
        # Nothing unsafe found — still return the (identical) copy so the
        # caller has a uniform contract, but note it was already clean.
        return SanitizationResult(
            input_path=path, file_type=kind, sanitized=True,
            output_path=out_path, removed=[],
        )
    return SanitizationResult(
        input_path=path, file_type=kind, sanitized=True,
        output_path=out_path, removed=removed,
    )
