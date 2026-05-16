"""Minimal text extraction for legacy OLE2 / CFB Office documents.

We don't reimplement Word's binary format here; instead, we use the soft
dependency `oletools` (already implied via `olefile`) to dump the WordDocument
stream's raw text. When `oletools` isn't present we fall back to extracting
printable ASCII from the document streams — enough for downstream T4 / T8
detectors to pattern-match injection content.
"""
from __future__ import annotations

import re
from ..base import ParsedDocument
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()

try:
    import olefile  # type: ignore
    _HAS_OLEFILE = True
except ImportError:
    _HAS_OLEFILE = False


# Streams that typically carry user-visible text in legacy Office formats.
_TEXT_STREAMS = (
    "WordDocument",
    "Workbook",
    "Book",
    "PowerPoint Document",
    "Pictures",  # PPT image stream; not useful for text but cheap to skip
)

_PRINTABLE_RE = re.compile(rb"[\x20-\x7e\n\r\t]{6,}")


def parse_ole(path: str, config: ScanConfig) -> ParsedDocument:
    """Parse a legacy OLE document and return a `ParsedDocument`."""
    if not _HAS_OLEFILE:
        return ParsedDocument(
            file_path=path, file_type="ole", text="", metadata={}
        )

    text_parts: list[str] = []
    metadata: dict = {}
    try:
        ole = olefile.OleFileIO(path)
    except Exception as exc:
        logger.debug("Failed to open OLE container %s: %s", path, exc)
        return ParsedDocument(file_path=path, file_type="ole", text="", metadata={})

    try:
        # Pull common properties via olefile's getproperties() if available.
        try:
            props = ole.getproperties("\x05SummaryInformation", convert_time=True)
            if props:
                # Keys are integer property IDs — map a few common ones.
                _PID = {2: "title", 3: "subject", 4: "author",
                        5: "keywords", 6: "comments", 7: "template",
                        8: "last_author", 9: "revision_number"}
                for k, v in props.items():
                    if isinstance(k, int) and k in _PID and isinstance(v, str):
                        metadata[_PID[k]] = v
        except Exception:
            pass

        # Extract printable runs from each candidate text stream.
        for entry in ole.listdir(streams=True, storages=False):
            if not entry:
                continue
            stream_name = entry[-1]
            if stream_name not in _TEXT_STREAMS:
                continue
            try:
                with ole.openstream(entry) as s:
                    raw = s.read(2 * 1024 * 1024)  # 2 MB cap per stream
            except Exception:
                continue
            for m in _PRINTABLE_RE.finditer(raw):
                text_parts.append(m.group(0).decode("latin-1", errors="replace"))
            if sum(len(p) for p in text_parts) > 1_000_000:
                break  # 1 MB of extracted text is plenty
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return ParsedDocument(
        file_path=path,
        file_type="ole",
        text="\n".join(text_parts),
        metadata=metadata,
    )
