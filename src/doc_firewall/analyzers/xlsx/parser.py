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
from ..ooxml_safe import MAX_PART_BYTES as _MAX_PARSE_BYTES  # noqa: F401 (re-exported)
from ..ooxml_safe import safe_xml_root as _safe_parse
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


def _extract_sheet_text(
    zf: zipfile.ZipFile, max_sheets: int = 200, max_part_size: int = 8 * 1024 * 1024
) -> tuple[str, list[str]]:
    """Extract plain text and hidden text from all worksheet XML parts."""
    
    # 1. Parse styles to find hidden fonts
    hidden_styles = set()
    if "xl/styles.xml" in zf.namelist():
        styles_root = _safe_parse(zf, "xl/styles.xml")
        if styles_root is not None:
            hidden_fonts = set()
            for i, font in enumerate(styles_root.findall(".//{*}fonts/{*}font")):
                # Check for hidden formatting (size 0/1 or white text)
                sz = font.find(".//{*}sz")
                if sz is not None and sz.get("val") in ["0", "1"]:
                    hidden_fonts.add(i)
                    continue
                color = font.find(".//{*}color")
                if color is not None and str(color.get("rgb", "")).upper().endswith("FFFFFF"):
                    hidden_fonts.add(i)
                    continue
                    
            for i, xf in enumerate(styles_root.findall(".//{*}cellXfs/{*}xf")):
                font_id_str = xf.get("fontId")
                if font_id_str and font_id_str.isdigit() and int(font_id_str) in hidden_fonts:
                    hidden_styles.add(i)

    # 2. XLSX uses a shared strings table for cell text
    shared_strings: List[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        root = _safe_parse(zf, "xl/sharedStrings.xml")
        if root is not None:
            for si in root.findall(".//{*}si"):
                parts = [t.text or "" for t in si.findall(".//{*}t") if t.text]
                shared_strings.append("".join(parts))

    # 3. Extract text from sheets
    sheet_files = sorted(
        [
            n
            for n in zf.namelist()
            if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
        ]
    )
    inline_texts: List[str] = []
    hidden_texts: List[str] = []
    
    for sheet_path in sheet_files[:max_sheets]:
        try:
            root = _safe_parse(zf, sheet_path, limit=max_part_size)
            if root is None:
                continue
            for c in root.findall(".//{*}c"):
                # Extract text correctly
                t_attr = c.get("t", "")
                s_attr = c.get("s", "0")
                
                cell_text = ""
                v_elem = c.find("{*}v") if hasattr(c, "find") else None
                
                if t_attr == "s" and v_elem is not None and v_elem.text and v_elem.text.isdigit():
                    idx = int(v_elem.text)
                    if idx < len(shared_strings):
                        cell_text = shared_strings[idx]
                elif t_attr == "inlineStr":
                    cell_text = " ".join(t.strip() for t in c.itertext() if t and t.strip())
                else:
                    if v_elem is not None and v_elem.text:
                        cell_text = v_elem.text.strip()
                    else:
                        cell_text = " ".join(t.strip() for t in c.itertext() if t and t.strip())

                if cell_text:
                    inline_texts.append(cell_text)
                    # Check for hidden style mapped from xl/styles.xml
                    if s_attr.isdigit() and int(s_attr) in hidden_styles:
                        hidden_texts.append(cell_text)
                        
        except Exception as e:
            logger.debug("Error reading %s: %s", sheet_path, e)

    combined = shared_strings + inline_texts
    return "\n".join(combined), hidden_texts


def _extract_core_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    root = _safe_parse(zf, "docProps/core.xml")
    if root is None:
        return meta
    for child in root:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child.text:
            meta[tag] = child.text.strip()
    return meta


def _extract_app_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    root = _safe_parse(zf, "docProps/app.xml")
    if root is None:
        return meta
    for child in root:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child.text:
            meta[tag] = child.text.strip()
    return meta


def _extract_custom_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    root = _safe_parse(zf, "docProps/custom.xml")
    if root is None:
        return meta
    try:
        for prop in root.findall(".//{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}property"):
            name = prop.get("name")
            value_elem = prop.find(".//")
            if name and value_elem is not None and value_elem.text:
                meta[name] = value_elem.text.strip()
    except Exception as e:
        logger.debug("Error reading custom.xml: %s", e)
    return meta

def _extract_comments(zf: zipfile.ZipFile, max_parts: int = 64) -> str:
    texts: list[str] = []
    seen = 0
    for n in zf.namelist():
        if n.startswith("xl/comments") and n.endswith(".xml"):
            seen += 1
            if seen > max_parts:
                break
            root = _safe_parse(zf, n)
            if root is None:
                continue
            for t in root.itertext():
                if t and t.strip():
                    texts.append(t.strip())
    return " ".join(texts)


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

            text, hidden_texts = _extract_sheet_text(
                zf,
                max_sheets=config.limits.max_pages,
                max_part_size=config.limits.max_xlsx_single_part_mb * 1024 * 1024,
            )
            core_meta = _extract_core_properties(zf)
            app_meta = _extract_app_properties(zf)
            custom_meta = _extract_custom_properties(zf)
            comments_text = _extract_comments(zf)
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
        **custom_meta,
        "sheet_count": sheet_count,
        "hidden_text": hidden_texts,
        "comments": comments_text,
    }

    return ParsedDocument(
        file_path=path,
        file_type="xlsx",
        text=text + "\n" + comments_text,
        metadata=metadata,
        xlsx={"sheet_count": sheet_count, "core": core_meta, "app": app_meta, "hidden_text": hidden_texts, "comments": comments_text},
    )
