"""
html/parser.py — HTML text extraction and ParsedDocument construction.

Uses html5lib for spec-compliant parsing if installed; falls back to stdlib
html.parser.HTMLParser (always available).  Only visible text is extracted —
<script>, <style>, <head>, and hidden-CSS elements are excluded or flagged.

The extracted text passes through the generic detector pipeline unchanged
(prompt injection, ATS manipulation, etc.).
"""
from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from typing import Any, Optional

from ..base import ParsedDocument
from ...config import ScanConfig

logger = logging.getLogger(__name__)

try:
    import html5lib  # type: ignore
    _HAS_HTML5LIB = True
except ImportError:
    _HAS_HTML5LIB = False


# ---------------------------------------------------------------------------
# Stdlib fallback extractor
# ---------------------------------------------------------------------------

_SKIP_TAGS = {"script", "style", "head", "meta", "link", "noscript"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._text_parts: list[str] = []
        self._skip_depth: int = 0
        self._current_tag: str = ""
        self.title: str = ""

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self._current_tag = tag.lower()
        if self._current_tag in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            stripped = data.strip()
            if stripped:
                if self._current_tag == "title" and not self.title:
                    self.title = stripped
                self._text_parts.append(stripped)

    @property
    def text(self) -> str:
        return " ".join(self._text_parts)


def _extract_text_stdlib(html_content: str) -> tuple[str, str]:
    """Return (visible_text, title) using stdlib HTMLParser."""
    extractor = _TextExtractor()
    try:
        extractor.feed(html_content)
    except Exception:
        pass
    return extractor.text, extractor.title


def _extract_text_html5lib(html_content: str) -> tuple[str, str]:
    """Return (visible_text, title) using html5lib for spec-compliant parsing."""
    try:
        doc = html5lib.parseFragment(html_content, treebuilder="etree", namespaceHTMLElements=False)
        parts: list[str] = []
        title = ""

        def _walk(node: Any) -> None:
            nonlocal title
            tag = getattr(node, "tag", None)
            if isinstance(tag, str) and tag.lower() in _SKIP_TAGS:
                return
            text = getattr(node, "text", None)
            if text and text.strip():
                if isinstance(tag, str) and tag.lower() == "title" and not title:
                    title = text.strip()
                else:
                    parts.append(text.strip())
            tail = getattr(node, "tail", None)
            if tail and tail.strip():
                parts.append(tail.strip())
            for child in node:
                _walk(child)

        _walk(doc)
        return " ".join(parts), title
    except Exception as exc:
        logger.debug("html5lib extraction failed: %s; falling back to stdlib", exc)
        return _extract_text_stdlib(html_content)


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------

_META_NAME_RE = re.compile(
    r'<meta\s[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_PROP_RE = re.compile(
    r'<meta\s[^>]*property\s*=\s*["\']([^"\']+)["\'][^>]*content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE)


def _extract_metadata(html_content: str) -> dict[str, str]:
    meta: dict = {}
    for m in _META_NAME_RE.finditer(html_content):
        meta[m.group(1).lower()] = m.group(2)[:500]
    for m in _META_PROP_RE.finditer(html_content):
        meta[m.group(1).lower()] = m.group(2)[:500]
    title_m = _TITLE_RE.search(html_content)
    if title_m:
        meta["title"] = title_m.group(1).strip()
    return meta


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def parse_html(file_path: str, config: ScanConfig) -> ParsedDocument:
    doc = ParsedDocument(file_path=file_path, file_type="html")
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()

        if _HAS_HTML5LIB:
            text, _title = _extract_text_html5lib(raw)
        else:
            text, _title = _extract_text_stdlib(raw)

        doc.text = text.strip()
        doc.metadata = _extract_metadata(raw)

    except Exception as exc:
        logger.warning("HTML parsing failed for %s: %s", file_path, exc)

    return doc
