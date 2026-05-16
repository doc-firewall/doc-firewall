from __future__ import annotations
import os

# Macro-enabled template extensions (item 0.12).
# These formats are structurally identical to their non-template counterparts
# but are purpose-built to execute macros on open and are higher-risk by design.
MACRO_TEMPLATE_EXTENSIONS = frozenset({
    ".dotm",   # Word macro-enabled template
    ".xltm",   # Excel macro-enabled template
    ".potm",   # PowerPoint macro-enabled template
    ".xlsm",   # Excel macro-enabled workbook
    ".pptm",   # PowerPoint macro-enabled presentation
    ".docm",   # Word macro-enabled document (already accepted; flagged separately)
})


def guess_file_type(path: str) -> str:
    ext = os.path.splitext(path.lower())[1]
    if ext == ".pdf":
        return "pdf"
    if ext in [".docx", ".docm", ".dotm"]:
        return "docx"
    if ext in [".pptx", ".pptm", ".potm"]:
        return "pptx"
    if ext in [".xlsx", ".xlsm", ".xlsb", ".xltm"]:
        return "xlsx"
    if ext == ".rtf":
        return "rtf"
    if ext in [".html", ".htm"]:
        return "html"
    # D.2: legacy OLE Office binary formats
    if ext in [".doc", ".dot"]:
        return "ole.doc"
    if ext in [".xls", ".xlt"]:
        return "ole.xls"
    if ext in [".ppt", ".pot"]:
        return "ole.ppt"
    # E.1: CSV / TSV
    if ext in [".csv", ".tsv"]:
        return "csv"
    # E.2: OpenDocument formats
    if ext == ".odt":
        return "odf.text"
    if ext == ".ods":
        return "odf.sheet"
    if ext == ".odp":
        return "odf.presentation"
    return "unknown"


def is_macro_template(path: str) -> bool:
    """Return True if the file extension indicates a macro-enabled template."""
    ext = os.path.splitext(path.lower())[1]
    return ext in MACRO_TEMPLATE_EXTENSIONS
