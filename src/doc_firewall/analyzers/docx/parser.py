from __future__ import annotations

import zipfile

from ...config import ScanConfig
from ...logger import get_logger
from ...utils.docling_convert import convert_with_docling
from ..base import ParsedDocument
from ..pptx.parser import (
    _extract_app_properties,
    _extract_core_properties,
    _extract_custom_properties,
)

logger = get_logger()


def parse_docx(path: str, config: ScanConfig) -> ParsedDocument:
    md, d = convert_with_docling(
        path,
        max_num_pages=config.limits.max_pages,
        max_file_size_bytes=config.limits.max_mb * 1024 * 1024,
        device=config.limits.docling_device,
    )
    # d is the merged metadata. W3 (0.5.0): Docling does not reliably surface
    # OOXML core/app/custom properties (title, keywords, description, custom
    # props) — exactly the metadata-injection surface — so extract them
    # directly from the package, mirroring the pptx/xlsx parsers. Without
    # this, an injection in docProps/core.xml <cp:keywords> never reaches the
    # metadata detectors.
    meta = dict(d)
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                core = _extract_core_properties(zf)
                app = _extract_app_properties(zf)
                custom = _extract_custom_properties(zf)
                for src in (core, app, custom):
                    for k, v in src.items():
                        meta.setdefault(k, v)
                meta["core"] = core
                meta["app"] = app
                meta["custom"] = custom
    except Exception as e:
        logger.debug("docx OOXML metadata extraction failed: %s", e)

    return ParsedDocument(
        file_path=path,
        file_type="docx",
        text=md,
        metadata=meta,
        docx={"structure": d.get("structure")},
    )
