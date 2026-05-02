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
    # Map pdf_comments into standard comments key for unified detector processing
    if "pdf_comments" in d and "comments" not in d:
        d["comments"] = d["pdf_comments"]
        
    return ParsedDocument(
        file_path=path,
        file_type="pdf",
        text=md,
        metadata=d,
        pdf={"structure": d.get("structure")},
    )
