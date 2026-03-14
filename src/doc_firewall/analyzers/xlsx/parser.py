from __future__ import annotations
import zipfile
from typing import Any, Dict, List

try:
    import defusedxml.ElementTree as ET  # noqa: F401
except ImportError as e:
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e

from ..base import ParsedDocument
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


def _extract_sheet_text(
    zf: zipfile.ZipFile, max_sheets: int = 200, max_part_size: int = 8 * 1024 * 1024
) -> str:
    """Extract plain text from all worksheet XML parts, up to max_sheets."""
    # XLSX uses a shared strings table for cell text
    shared_strings: List[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        try:
            info = zf.getinfo("xl/sharedStrings.xml")
            if info.file_size <= 16 * 1024 * 1024:
                with zf.open("xl/sharedStrings.xml") as f:
                    root = ET.parse(f).getroot()
                for si in root.findall(".//{*}si"):
                    parts = [t.text or "" for t in si.findall(".//{*}t") if t.text]
                    shared_strings.append("".join(parts))
        except Exception as e:
            logger.debug("Error reading sharedStrings.xml: %s", e)

    # Also extract inline strings from sheets
    sheet_files = sorted(
        [
            n
            for n in zf.namelist()
            if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
        ]
    )
    inline_texts: List[str] = []
    for sheet_path in sheet_files[:max_sheets]:
        try:
            info = zf.getinfo(sheet_path)
            if info.file_size > max_part_size:
                continue
            with zf.open(sheet_path) as f:
                root = ET.parse(f).getroot()
            for c in root.findall(".//{*}c"):
                t_attr = c.get("t", "")
                v_elem = c.find("{*}v") if hasattr(c, "find") else None
                # Try itertext as fallback
                cell_text = " ".join(t.strip() for t in c.itertext() if t and t.strip())
                if cell_text:
                    inline_texts.append(cell_text)
        except Exception as e:
            logger.debug("Error reading %s: %s", sheet_path, e)

    combined = shared_strings + inline_texts
    return "\n".join(combined)


def _extract_core_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if "docProps/core.xml" not in zf.namelist():
        return meta
    try:
        with zf.open("docProps/core.xml") as f:
            root = ET.parse(f).getroot()
        for child in root:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text:
                meta[tag] = child.text.strip()
    except Exception as e:
        logger.debug("Error reading core.xml: %s", e)
    return meta


def _extract_app_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if "docProps/app.xml" not in zf.namelist():
        return meta
    try:
        with zf.open("docProps/app.xml") as f:
            root = ET.parse(f).getroot()
        for child in root:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text:
                meta[tag] = child.text.strip()
    except Exception as e:
        logger.debug("Error reading app.xml: %s", e)
    return meta


def parse_xlsx(path: str, config: ScanConfig) -> ParsedDocument:
    """Parse an XLSX file: extract text from sheets and core metadata."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            # Zip Bomb Protection: Abort parsing if total uncompressed size exceeds limit
            total_uncompressed = sum(z.file_size for z in zf.infolist())
            if (
                total_uncompressed
                > config.limits.max_xlsx_total_uncompressed_mb * 1024 * 1024
            ):
                logger.warning(
                    "XLSX parse aborted (Zip bomb detected)",
                    path=path,
                    uncompressed_mb=total_uncompressed / (1024 * 1024),
                )
                return ParsedDocument(
                    file_path=path, file_type="xlsx", text="", metadata={}
                )

            text = _extract_sheet_text(
                zf,
                max_sheets=config.limits.max_pages,
                max_part_size=config.limits.max_xlsx_single_part_mb * 1024 * 1024,
            )
            core_meta = _extract_core_properties(zf)
            app_meta = _extract_app_properties(zf)
            sheet_count = len(
                [
                    n
                    for n in zf.namelist()
                    if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
                ]
            )
    except zipfile.BadZipFile as e:
        logger.warning("XLSX parse error (bad zip)", path=path, error=str(e))
        return ParsedDocument(file_path=path, file_type="xlsx", text="", metadata={})

    metadata: Dict[str, Any] = {
        **core_meta,
        **app_meta,
        "sheet_count": sheet_count,
    }

    return ParsedDocument(
        file_path=path,
        file_type="xlsx",
        text=text,
        metadata=metadata,
        xlsx={"sheet_count": sheet_count, "core": core_meta, "app": app_meta},
    )
