"""ODF deep-scan parser. Extracts visible body text + metadata so the
standard detector pipeline (T4 prompt injection, T8 metadata, T9 ATS,
T10/T11/T12) applies to ODF documents.
"""
from __future__ import annotations

import re
import zipfile

from ..base import ParsedDocument
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


# Strip XML tags but keep their text content.
_TAG_RE = re.compile(rb"<[^>]+>")
# Replace common XML entities AFTER tag stripping.
_ENTITIES = {b"&amp;": b"&", b"&lt;": b"<", b"&gt;": b">",
             b"&quot;": b'"', b"&apos;": b"'", b"&nbsp;": b" "}


def _strip_xml_tags(xml_bytes: bytes) -> str:
    body = _TAG_RE.sub(b" ", xml_bytes)
    for ent, repl in _ENTITIES.items():
        body = body.replace(ent, repl)
    text = body.decode("utf-8", errors="replace")
    # Collapse whitespace
    return re.sub(r"\s+", " ", text).strip()


def _parse_meta(meta_xml: bytes) -> dict:
    """Pull Dublin Core fields from meta.xml."""
    meta: dict = {}
    for key, tag in [
        ("title", "dc:title"),
        ("subject", "dc:subject"),
        ("description", "dc:description"),
        ("creator", "meta:initial-creator"),
        ("keywords", "meta:keyword"),
    ]:
        m = re.search(
            rb"<" + tag.encode() + rb"[^>]*>([^<]*)</" + tag.encode() + rb">",
            meta_xml, re.IGNORECASE,
        )
        if m:
            val = m.group(1).decode("utf-8", errors="replace").strip()
            if val:
                meta[key] = val
    return meta


def parse_odf(path: str, config: ScanConfig) -> ParsedDocument:
    text = ""
    metadata: dict = {"format": "odf"}

    try:
        with zipfile.ZipFile(path, "r") as zf:
            try:
                content_bytes = zf.read("content.xml")[: 4 * 1024 * 1024]
            except KeyError:
                content_bytes = b""
            try:
                meta_bytes = zf.read("meta.xml")[: 256 * 1024]
            except KeyError:
                meta_bytes = b""

            text = _strip_xml_tags(content_bytes)
            metadata.update(_parse_meta(meta_bytes))
    except OSError as exc:
        logger.debug("ODF parse failed for %s: %s", path, exc)

    return ParsedDocument(
        file_path=path,
        file_type="odf",
        text=text,
        metadata=metadata,
    )
