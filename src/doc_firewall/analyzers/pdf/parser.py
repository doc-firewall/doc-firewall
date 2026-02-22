from __future__ import annotations
from ..base import ParsedDocument
from ...config import ScanConfig
from ...utils.docling_convert import convert_with_docling


def parse_pdf(path: str, config: ScanConfig) -> ParsedDocument:
    md, d = convert_with_docling(
        path,
        max_num_pages=config.limits.max_pages,
        max_file_size_bytes=config.limits.max_mb * 1024 * 1024,
    )
    # d is the merged metadata
    return ParsedDocument(
        file_path=path,
        file_type="pdf",
        text=md,
        metadata=d,
        pdf={"structure": d.get("structure")},
    )
