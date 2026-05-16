"""CSV deep-scan parser. Extracts cell text + per-column tokens so the
standard T4 / T8 / T9 detectors apply to CSV content.
"""
from __future__ import annotations

import csv

from ..base import ParsedDocument
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


def parse_csv(path: str, config: ScanConfig) -> ParsedDocument:
    text_parts: list[str] = []
    metadata: dict = {"format": "csv", "columns": []}
    column_text: dict[int, list[str]] = {}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(8192)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
            except csv.Error:
                dialect = csv.excel
            reader = csv.reader(f, dialect=dialect)
            for row_idx, row in enumerate(reader):
                line_cells: list[str] = []
                for col_idx, cell in enumerate(row):
                    if cell:
                        line_cells.append(cell)
                        column_text.setdefault(col_idx, []).append(cell)
                if line_cells:
                    text_parts.append(" ".join(line_cells))
                # Cap extracted text to bound memory
                if sum(len(p) for p in text_parts) > 2 * 1024 * 1024:
                    break
    except OSError as exc:
        logger.debug("CSV parse failed for %s: %s", path, exc)

    metadata["columns"] = [
        {"index": idx, "samples": vals[:5]} for idx, vals in column_text.items()
    ]

    return ParsedDocument(
        file_path=path,
        file_type="csv",
        text="\n".join(text_parts),
        metadata=metadata,
    )
