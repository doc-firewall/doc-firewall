"""
rtf/parser.py — RTF text extraction and ParsedDocument construction.

Uses `striprtf` if installed; falls back to a conservative regex stripper
that removes RTF control words and groups, leaving visible text.

The extracted text is fed to the generic detector pipeline (prompt injection,
obfuscation, ATS manipulation, etc.) exactly like PDF/DOCX text.
"""
from __future__ import annotations

import re
import logging

from ..base import ParsedDocument
from ...config import ScanConfig

logger = logging.getLogger(__name__)

try:
    from striprtf.striprtf import rtf_to_text as _striprtf_to_text
    _HAS_STRIPRTF = True
except ImportError:
    _HAS_STRIPRTF = False


# ---------------------------------------------------------------------------
# Fallback regex stripper — used when striprtf is not installed
# ---------------------------------------------------------------------------

_RTF_CONTROL_RE = re.compile(
    r"\\[a-z*]+[-\d]*[ ]?"   # control words: \word or \word-123
    r"|\\'"                   # hex-encoded char escape \'XX start (handled below)
    r"|[{}]"                  # group delimiters
    r"|\\[^a-z]",             # control symbols: \*, \{, etc.
    re.IGNORECASE,
)
_RTF_HEX_CHAR_RE = re.compile(r"\\'([0-9a-fA-F]{2})")


def _fallback_rtf_to_text(content: str) -> str:  # noqa: E501
    """Minimal RTF text extractor when striprtf is unavailable."""
    # Decode hex-escaped chars first
    text = _RTF_HEX_CHAR_RE.sub(
        lambda m: chr(int(m.group(1), 16)), content
    )
    # Strip all RTF markup
    text = _RTF_CONTROL_RE.sub("", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

def parse_rtf(file_path: str, config: ScanConfig) -> ParsedDocument:
    doc = ParsedDocument(file_path=file_path, file_type="rtf")
    try:
        with open(file_path, "r", encoding="latin-1", errors="replace") as fh:
            raw = fh.read()

        if _HAS_STRIPRTF:
            text = _striprtf_to_text(raw)
        else:
            logger.debug("striprtf not installed; using fallback RTF text extractor")
            text = _fallback_rtf_to_text(raw)

        doc.text = text.strip()

        # Extract basic metadata from the {\\info} block if present
        meta: dict = {}
        for field in ("author", "operator", "company", "title", "subject"):
            m = re.search(rf"\{{\\{field}\s+([^}}]+)\}}", raw, re.IGNORECASE)
            if m:
                meta[field] = m.group(1).strip()
        doc.metadata = meta

    except Exception as exc:
        logger.warning("RTF parsing failed for %s: %s", file_path, exc)

    return doc
