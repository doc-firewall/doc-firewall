from __future__ import annotations
import zipfile
from typing import Any, Dict

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

_NS_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_NS_DC = "{http://purl.org/dc/elements/1.1/}"
_NS_CP = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"


def _extract_slide_text(
    zf: zipfile.ZipFile, max_slides: int = 500, max_part_size: int = 8 * 1024 * 1024
) -> tuple[str, list[str]]:
    """Extract plain text and hidden text from all slide XML parts."""
    texts: list[str] = []
    hidden_texts: list[str] = []
    slide_files = sorted(
        [
            n
            for n in zf.namelist()
            if n.startswith("ppt/slides/slide") and n.endswith(".xml")
        ]
    )
    for slide_path in slide_files[:max_slides]:
        try:
            info = zf.getinfo(slide_path)
            if info.file_size > max_part_size:
                continue
            with zf.open(slide_path) as f:
                root = ET.parse(f).getroot()
            
            slide_text = " ".join(t.strip() for t in root.itertext() if t and t.strip())
            if slide_text:
                texts.append(slide_text)
                
            # Scan for hidden text (T9 ATS Manipulation)
            for r in root.findall('.//a:r', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'}):
                rPr = r.find('.//a:rPr', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                t = r.find('.//a:t', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                if rPr is not None and t is not None and t.text and t.text.strip():
                    text_val = t.text.strip()
                    # Font size 0 or 1
                    sz = rPr.get('sz')
                    if sz in ["0", "1"]:
                        hidden_texts.append(text_val)
                        continue
                    # White text (srgbClr val="FFFFFF") or fully transparent
                    solidFill = rPr.find('.//a:solidFill', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                    if solidFill is not None:
                        srgbClr = solidFill.find('.//a:srgbClr', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                        if srgbClr is not None and srgbClr.get('val', '').upper() == 'FFFFFF':
                            hidden_texts.append(text_val)
                            continue
                        alpha = solidFill.find('.//a:alpha', {'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                        if alpha is not None and alpha.get('val') == '0':
                            hidden_texts.append(text_val)
                            continue

        except Exception as e:
            logger.debug("Error reading %s: %s", slide_path, e)
    return "\n".join(texts), hidden_texts


def _extract_core_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Extract Dublin Core / OPC core properties from docProps/core.xml."""
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
    """Extract app properties from docProps/app.xml."""
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


def _extract_custom_properties(zf: zipfile.ZipFile) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if "docProps/custom.xml" not in zf.namelist():
        return meta
    try:
        with zf.open("docProps/custom.xml") as f:
            root = ET.parse(f).getroot()
        for prop in root.findall(".//{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}property"):
            name = prop.get("name")
            value_elem = prop.find(".//")
            if name and value_elem is not None and value_elem.text:
                meta[name] = value_elem.text.strip()
    except Exception as e:
        logger.debug("Error reading custom.xml: %s", e)
    return meta

def _extract_comments(zf: zipfile.ZipFile) -> str:
    texts: list[str] = []
    for n in zf.namelist():
        if n.startswith("ppt/comments/comment") and n.endswith(".xml"):
            try:
                with zf.open(n) as f:
                    root = ET.parse(f).getroot()
                for t in root.itertext():
                    if t and t.strip():
                        texts.append(t.strip())
            except Exception:
                pass
    return " ".join(texts)


def parse_pptx(path: str, config: ScanConfig) -> ParsedDocument:
    """Parse a PPTX file: extract text from slides and core metadata."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            # Zip Bomb Protection: Abort parsing if total uncompressed size exceeds limit
            total_uncompressed = sum(z.file_size for z in zf.infolist())
            if (
                total_uncompressed
                > config.limits.max_pptx_total_uncompressed_mb * 1024 * 1024
            ):
                logger.warning(
                    "PPTX parse aborted (Zip bomb detected)",
                    path=path,
                    uncompressed_mb=total_uncompressed / (1024 * 1024),
                )
                return ParsedDocument(
                    file_path=path, file_type="pptx", text="", metadata={}
                )

            text, hidden_texts = _extract_slide_text(
                zf,
                max_slides=config.limits.max_pages,
                max_part_size=config.limits.max_pptx_single_part_mb * 1024 * 1024,
            )
            core_meta = _extract_core_properties(zf)
            app_meta = _extract_app_properties(zf)
            custom_meta = _extract_custom_properties(zf)
            comments_text = _extract_comments(zf)
            slide_count = len(
                [
                    n
                    for n in zf.namelist()
                    if n.startswith("ppt/slides/slide") and n.endswith(".xml")
                ]
            )
    except zipfile.BadZipFile as e:
        logger.warning("PPTX parse error (bad zip)", path=path, error=str(e))
        return ParsedDocument(file_path=path, file_type="pptx", text="", metadata={})

    metadata: Dict[str, Any] = {
        **core_meta,
        **app_meta,
        **custom_meta,
        "slide_count": slide_count,
        "hidden_text": hidden_texts,
        "comments": comments_text,
    }

    return ParsedDocument(
        file_path=path,
        file_type="pptx",
        text=text + "\n" + comments_text,
        metadata=metadata,
        pptx={"slide_count": slide_count, "core": core_meta, "app": app_meta, "hidden_text": hidden_texts, "comments": comments_text},
    )
