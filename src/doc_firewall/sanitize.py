"""W3 (0.5.0) — document sanitization for safe LLM/RAG ingestion.

Detection answers "is this dangerous?"; sanitization answers "give me a safe
version I can ingest." For the RAG/LLM use case the high-value action is
often not BLOCK but a *cleaned copy*: strip the hidden/invisible text, drop
dangerous metadata, remove active content, and neutralise located
injections — while preserving the visible content.

``Scanner.sanitize(path)`` (or the module-level ``sanitize_file``) returns a
``SanitizationResult`` with the path to a cleaned copy plus an auditable
``removed`` list (what was stripped, and why). Formats without a sanitizer
return ``sanitized=False`` with a reason, so a caller can fall back to BLOCK.

Each sanitizer is conservative: it removes only constructs that are
unambiguously unsafe or invisible, leaving the visible document intact, and
the result is designed to re-scan ALLOW.
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .logger import get_logger

logger = get_logger()


@dataclass
class Removal:
    """One thing the sanitizer stripped, for the audit trail."""

    kind: str                       # "hidden_text" | "metadata" | "macro" | ...
    detail: str                     # human description
    location: Optional[str] = None  # part / field where it lived
    excerpt: Optional[str] = None   # the offending content (capped)

    def to_dict(self) -> Dict[str, Any]:
        d = {"kind": self.kind, "detail": self.detail}
        if self.location:
            d["location"] = self.location
        if self.excerpt:
            d["excerpt"] = self.excerpt[:200]
        return d


@dataclass
class SanitizationResult:
    """Outcome of a sanitize() call."""

    input_path: str
    file_type: str
    sanitized: bool                       # True if a cleaned copy was produced
    output_path: Optional[str] = None     # cleaned copy (caller owns/deletes it)
    removed: List[Removal] = field(default_factory=list)
    reason: Optional[str] = None          # why not sanitized (when sanitized=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_path": self.input_path,
            "file_type": self.file_type,
            "sanitized": self.sanitized,
            "output_path": self.output_path,
            "removed": [r.to_dict() for r in self.removed],
            "reason": self.reason,
        }


# Every removal category a sanitizer can act on.
ALL_CATEGORIES = (
    "hidden_text", "metadata", "macro", "active_content",
    "embedded_file", "formula_injection",
)


def category_enabled(category: str, config: Any) -> bool:
    """Whether ``category`` should be stripped, per config. Default: strip
    all (so a None config / a config without the field removes everything)."""
    cats = getattr(config, "sanitize_remove_categories", None)
    if cats is None:
        return True
    return category in cats


def _tmp_out(suffix: str) -> str:
    fd, p = tempfile.mkstemp(suffix=suffix, prefix="docfw_clean_")
    os.close(fd)
    return p


def _resolve_out(suffix: str, output_path: Optional[str]) -> str:
    return output_path if output_path else _tmp_out(suffix)


def sanitize_file(
    path: str,
    file_type: str,
    config: Any = None,
    output_path: Optional[str] = None,
) -> SanitizationResult:
    """Dispatch to the per-format sanitizer. Never raises — on error returns
    ``sanitized=False`` so the caller can fall back to BLOCK.

    ``output_path`` lets the caller choose where the cleaned copy is written
    (default: a temp file the caller owns). The original is never modified.
    """
    ft = (file_type or "").lower()

    # Master switch: respect a user who has disabled sanitization.
    if config is not None and not getattr(config, "enable_sanitization", True):
        return SanitizationResult(
            input_path=path, file_type=ft, sanitized=False,
            reason="sanitization disabled by config (enable_sanitization=False)",
        )

    try:
        if ft.startswith(("docx", "docm")):
            from .sanitizers.ooxml import sanitize_ooxml
            return sanitize_ooxml(path, "docx", config, output_path)
        if ft.startswith(("pptx", "pptm")):
            from .sanitizers.ooxml import sanitize_ooxml
            return sanitize_ooxml(path, "pptx", config, output_path)
        if ft.startswith(("xlsx", "xlsm")):
            from .sanitizers.ooxml import sanitize_ooxml
            return sanitize_ooxml(path, "xlsx", config, output_path)
        if ft.startswith("pdf"):
            from .sanitizers.pdf import sanitize_pdf
            return sanitize_pdf(path, config, output_path)
        if ft.startswith(("csv", "tsv")):
            from .sanitizers.text import sanitize_csv
            return sanitize_csv(path, config, output_path)
        if ft.startswith(("html", "htm")):
            from .sanitizers.text import sanitize_html
            return sanitize_html(path, config, output_path)
    except Exception as e:  # never let a sanitizer crash the caller
        logger.debug("sanitize_file error for %s: %s", path, e)
        return SanitizationResult(
            input_path=path, file_type=ft, sanitized=False,
            reason=f"sanitizer error: {type(e).__name__}",
        )
    return SanitizationResult(
        input_path=path, file_type=ft, sanitized=False,
        reason=f"no sanitizer available for file type '{ft}' — cannot make a "
        "safe copy; treat as BLOCK",
    )
