"""Bounded XML-member reading for ZIP-based formats (OOXML + ODF).

A malicious workbook/presentation/document can declare a small ``file_size``
in the ZIP central directory while its member decompresses to gigabytes (a
decompression bomb). zipfile's ``read(n)`` stops decompressing after ``n``
bytes, so reading every member through these helpers — never ``zf.read(name)``
or ``ET.parse(zf.open(name))`` directly — bounds memory regardless of the
declared size. An oversized member is skipped, not expanded into a giant DOM.
"""
from __future__ import annotations

import zipfile

try:
    import defusedxml.ElementTree as ET
except ImportError as e:  # pragma: no cover - import guard
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e

from ..logger import get_logger

logger = get_logger()

# Default hard decompression cap per XML part.
MAX_PART_BYTES = 16 * 1024 * 1024


def safe_member_bytes(
    zf: zipfile.ZipFile, name: str, limit: int = MAX_PART_BYTES
) -> bytes | None:
    """Return up to ``limit`` decompressed bytes of member ``name``, or
    ``None`` if it is absent or exceeds the cap. Reads ``limit + 1`` bytes so
    an over-cap member is detected without being fully decompressed."""
    try:
        with zf.open(name) as f:
            data = f.read(limit + 1)
    except Exception as e:
        logger.debug("Error reading %s: %s", name, e)
        return None
    if len(data) > limit:
        logger.warning("ZIP part exceeds read cap; skipping", part=name)
        return None
    return data


def safe_xml_root(
    zf: zipfile.ZipFile, name: str, limit: int = MAX_PART_BYTES
):
    """Parse member ``name`` as XML with a hard decompression cap. Returns the
    root element, or ``None`` if the member is absent, oversized, or malformed.
    Never raises."""
    data = safe_member_bytes(zf, name, limit)
    if not data:
        return None
    try:
        return ET.fromstring(data)
    except Exception as e:
        logger.debug("Error parsing %s: %s", name, e)
        return None
