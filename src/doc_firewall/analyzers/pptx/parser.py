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
) -> str:
    """Extract plain text from all slide XML parts, up to max_slides."""
    texts: list[str] = []
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
        except Exception as e:
            logger.debug("Error reading %s: %s", slide_path, e)
    return "\n".join(texts)


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

            text = _extract_slide_text(
                zf,
                max_slides=config.limits.max_pages,
                max_part_size=config.limits.max_pptx_single_part_mb * 1024 * 1024,
            )
            core_meta = _extract_core_properties(zf)
            app_meta = _extract_app_properties(zf)
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
        "slide_count": slide_count,
    }

    return ParsedDocument(
        file_path=path,
        file_type="pptx",
        text=text,
        metadata=metadata,
        pptx={"slide_count": slide_count, "core": core_meta, "app": app_meta},
    )
