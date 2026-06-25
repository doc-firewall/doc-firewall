"""W3 (0.5.0) — CSV / HTML sanitizers (stdlib only)."""
from __future__ import annotations

import re
from typing import Any, List, Optional

from ..sanitize import (
    Removal,
    SanitizationResult,
    _resolve_out,
    category_enabled,
)

# A CSV cell that a spreadsheet would evaluate as a formula starts with one
# of these. The standard mitigation is to prefix a single quote so the cell
# is treated as literal text.
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_cell(cell: str) -> tuple[str, bool]:
    s = cell.lstrip()
    if s[:1] in _FORMULA_LEAD:
        return "'" + cell, True
    return cell, False


def sanitize_csv(
    path: str, config: Any = None, output_path: Optional[str] = None
) -> SanitizationResult:
    removed: List[Removal] = []
    if not category_enabled("formula_injection", config):
        # Nothing else to strip in a CSV — return an identical copy.
        out_path = _resolve_out(".csv", output_path)
        with open(path, "rb") as src, open(out_path, "wb") as dst:
            dst.write(src.read())
        return SanitizationResult(
            input_path=path, file_type="csv", sanitized=True,
            output_path=out_path, removed=[],
        )
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        text = f.read()
    out_lines: List[str] = []
    for line in text.splitlines(keepends=False):
        # Naive split on comma/semicolon/tab is sufficient for neutralising
        # leading-character formula injection (the only CSV exec vector).
        delim = "\t" if "\t" in line and "," not in line else ","
        cells = line.split(delim)
        new_cells = []
        for c in cells:
            nc, changed = _neutralize_cell(c)
            if changed:
                removed.append(Removal(
                    kind="formula_injection",
                    detail="prefixed formula-leading cell with apostrophe",
                    excerpt=c.strip(),
                ))
            new_cells.append(nc)
        out_lines.append(delim.join(new_cells))

    out_path = _resolve_out(".csv", output_path)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write("\n".join(out_lines))
    return SanitizationResult(
        input_path=path, file_type="csv", sanitized=True,
        output_path=out_path, removed=removed,
    )


# The closing tag matches the way browsers actually terminate a script element:
# `</script` followed by ANY characters up to the next `>` (e.g. `</script foo>`,
# `</script\t\n bar>`). The previous `</script\s*>` only matched optional
# whitespace, so `<script>evil()</script x>` slipped through unsanitised
# (CodeQL js/bad-tag-filter). `\b` keeps `</scriptx>` from matching.
_SCRIPT_RE = re.compile(r"<script\b.*?</script\b[^>]*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_EVENT_ATTR_RE = re.compile(r"\son[a-z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_JS_HREF_RE = re.compile(r"(href|src)\s*=\s*(\"|')\s*javascript:[^\"']*\2", re.IGNORECASE)
# Inline-styled hidden text (display:none / visibility:hidden / font-size:0 /
# opacity:0 / color matching background). We strip the whole element's style
# attribute rather than the element, preserving the text for the reader if it
# was meant to be visible — but neutralising the concealment.
_HIDDEN_STYLE_RE = re.compile(
    r"style\s*=\s*(\"|')[^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)"
    r"[^\"']*\1",
    re.IGNORECASE,
)


def sanitize_html(
    path: str, config: Any = None, output_path: Optional[str] = None
) -> SanitizationResult:
    removed: List[Removal] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        html = f.read()

    do_active = category_enabled("active_content", config)
    do_hidden = category_enabled("hidden_text", config)

    def _drop(rx: re.Pattern, kind: str, detail: str, s: str) -> str:
        def _r(m: re.Match) -> str:
            removed.append(Removal(kind=kind, detail=detail, excerpt=m.group(0)))
            return ""
        return rx.sub(_r, s)

    if do_active:
        html = _drop(_SCRIPT_RE, "active_content", "removed <script> block", html)
        html = _drop(_SCRIPT_OPEN_RE, "active_content", "removed stray <script> tag", html)
        html = _drop(_EVENT_ATTR_RE, "active_content", "removed inline event handler", html)
        html = _drop(_JS_HREF_RE, "active_content", "removed javascript: URL", html)
    if do_hidden:
        html = _drop(_HIDDEN_STYLE_RE, "hidden_text", "removed hiding style attribute", html)

    out_path = _resolve_out(".html", output_path)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return SanitizationResult(
        input_path=path, file_type="html", sanitized=True,
        output_path=out_path, removed=removed,
    )
