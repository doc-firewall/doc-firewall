from __future__ import annotations
import os
import zipfile
import re
from functools import lru_cache
from typing import Any, Dict, Tuple
from ..logger import get_logger

logger = get_logger()

try:
    import defusedxml.ElementTree as ET
except ImportError as e:
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e

# Disable OCR model downloads globally
os.environ["DOCLING_DISABLE_OCR"] = "1"
os.environ["RAPIDOCR_DISABLE_AUTO_DOWNLOAD"] = "1"

try:
    from docling.document_converter import DocumentConverter, PdfFormatOption
    from docling.datamodel.pipeline_options import PdfPipelineOptions

    HAS_DOCLING = True
except ImportError:
    HAS_DOCLING = False

if HAS_DOCLING:

    @lru_cache(maxsize=1)
    def _converter() -> DocumentConverter:
        pipeline_options = PdfPipelineOptions()
        pipeline_options.do_ocr = False
        pipeline_options.do_table_structure = False
        pipeline_options.table_structure_options.do_cell_matching = False

        return DocumentConverter(
            format_options={
                PdfFormatOption: PdfFormatOption(pipeline_options=pipeline_options)
            }
        )


# Namespaces
NS_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
NS_DC = "{http://purl.org/dc/elements/1.1/}"
NS_CP = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"


def _safe_read_xml(
    z: zipfile.ZipFile, filename: str, max_size_mb: int = 10
) -> ET.Element | None:
    """Safe extraction of XML from zip with size limits and XXE protection."""
    try:
        info = z.getinfo(filename)
        if info.file_size > max_size_mb * 1024 * 1024:
            # File too big, skip or raise
            return None

        with z.open(filename) as f:
            # defusedxml helps prevent Billion Laughs / XXE
            tree = ET.parse(f)
            return tree.getroot()
    except Exception:
        return None


def _get_text_recursive(elem: ET.Element) -> str:
    """Recursively extract text from element, adding spaces for block elements
    if needed."""
    return "".join(elem.itertext())


def _fallback_docx(path: str) -> Tuple[str, Dict[str, Any]]:
    logger.debug("Entering _fallback_docx", path=path)
    text = ""
    meta = {}
    try:
        with zipfile.ZipFile(path, "r") as z:
            # --- 1. Content Extraction (word/document.xml) ---
            root = _safe_read_xml(z, "word/document.xml")
            if root is not None:
                # Check for hidden text (T9)
                # Logic: Iterate over runs <w:r>. If a run has
                # <w:rPr><w:vanish/></w:rPr>, the text in <w:t> is hidden.
                # Structure:
                # <w:r>
                #   <w:rPr> <w:vanish/> </w:rPr>
                #   <w:t>Hidden Text</w:t>
                # </w:r>

                hidden_texts = []
                full_text_parts = []

                # Iterate over all runs
                for run in root.iter(f"{NS_W}r"):  # Find all <w:r>
                    # Check properties
                    rPr = run.find(f"{NS_W}rPr")
                    is_hidden = False
                    if rPr is not None:
                        if rPr.find(f"{NS_W}vanish") is not None:
                            is_hidden = True

                    # Get text
                    t_elems = run.findall(f"{NS_W}t")
                    run_text = "".join([t.text for t in t_elems if t.text])

                    if is_hidden and run_text:
                        hidden_texts.append(run_text)

                    if run_text:
                        full_text_parts.append(run_text)

                text = " ".join(full_text_parts)

                if hidden_texts:
                    meta["has_hidden_tags"] = True
                    meta["hidden_text"] = hidden_texts

            # --- 2. Comments (word/comments.xml) ---
            if "word/comments.xml" in z.namelist():
                c_root = _safe_read_xml(z, "word/comments.xml")
                if c_root is not None:
                    comments = []
                    # Extract text from all <w:t>
                    for t in c_root.iter(f"{NS_W}t"):
                        if t.text:
                            comments.append(t.text)
                    if comments:
                        meta["comments"] = comments

            # --- 3. Core Properties (docProps/core.xml) ---
            if "docProps/core.xml" in z.namelist():
                cp_root = _safe_read_xml(z, "docProps/core.xml")
                if cp_root is not None:
                    # Map standard fields
                    # Standard names: dc:title, dc:creator, dc:description,
                    # cp:lastModifiedBy, cp:category, cp:contentStatus
                    mapping = {
                        f"{NS_DC}title": "title",
                        f"{NS_DC}subject": "subject",
                        f"{NS_DC}creator": "creator",
                        f"{NS_DC}description": "description",
                        f"{NS_CP}lastModifiedBy": "lastModifiedBy",
                        f"{NS_CP}category": "category",
                        f"{NS_CP}contentStatus": "contentStatus",
                    }

                    for tag, key in mapping.items():
                        # We use .iter to find the element regardless of root depth
                        # (though core props usually flat)
                        # Actually core props are direct children of root often.
                        # iterate all children to handle potential namespace prefix
                        # issues in finding?
                        # Using find with explicit NS is best.

                        elem = cp_root.find(tag)
                        if elem is None:
                            # Try finding anywhere if structure varies? No, core.xml
                            # is standard.
                            pass

                        # Fallback: simple iteration if find fails due to NS quirk
                        if elem is not None and elem.text:
                            meta[key] = elem.text
                        else:
                            # Try iterate just in case
                            for child in cp_root:
                                if child.tag == tag and child.text:
                                    meta[key] = child.text

            # --- 4. Custom Properties (docProps/custom.xml) ---
            if "docProps/custom.xml" in z.namelist():
                # Custom props are:
                # <property ... name="foo"><vt:lpwstr>bar</vt:lpwstr></property>
                cust_root = _safe_read_xml(z, "docProps/custom.xml")
                if cust_root is not None:
                    # Namespace for custom props is typically: http://schemas.openxmlformats.org/officeDocument/2006/custom-properties
                    # but finding elements by local name is safer here.
                    for prop in cust_root:
                        name = prop.get("name")
                        # Value is in the child
                        val_text = "".join(prop.itertext())
                        if name and val_text:
                            meta[name.lower()] = val_text

            # --- 5. T7: Embedded Objects / OLE ---
            # Check for binary files in embeddings/ folder
            for name in z.namelist():
                if (
                    name.startswith("word/embeddings/")
                    or name.startswith("word/media/")
                    or name.endswith(".bin")
                    or name.endswith(".exe")
                ):
                    if (
                        name.endswith(".bin")
                        or name.endswith(".exe")
                        or "ole" in name.lower()
                    ):
                        # Sanity check size for OLE
                        info = z.getinfo(name)
                        if info.file_size < 1 * 1024 * 1024:
                            # 1MB per-blob limit (hex encoding doubles memory)
                            with z.open(name) as f:
                                data = f.read(1 * 1024 * 1024)
                                # Store first 4KB hex for signature analysis
                                hex_str = data[:4096].hex()
                                meta.setdefault("hex_blobs", []).append(hex_str)

    except Exception as e:
        logger.warning("Fallback DOCX error", path=path, error=str(e))
        pass
    return text, meta


# Maximum bytes for fallback PDF parser to prevent OOM on oversized files
_MAX_FALLBACK_READ_BYTES = 8 * 1024 * 1024  # 8 MB


def _fallback_pdf(path: str) -> Tuple[str, Dict[str, Any]]:
    text = ""
    meta = {}
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_FALLBACK_READ_BYTES)

            # --- 1. Metadata Injection (T8) [MOVED UP] ---
            # Look for /Title ( ... ) or /Subject ( ... )
            # This is a simple regex for standard PDF dictionnaries
            for field in [
                b"Title",
                b"Author",
                b"Subject",
                b"Creator",
                b"Producer",
                b"Keywords",
            ]:
                # Regex handles escaped parentheses: \(( (?: [^)\\] | \\. )* )\)
                m = re.search(b"/" + field + b"\\s*\\(((?:[^)\\\\]|\\\\.)*)\\)", data)
                if m:
                    try:
                        raw_val = m.group(1).decode("utf-8", errors="ignore")
                        # Basic PDF Unescaping
                        val = (
                            raw_val.replace("\\(", "(")
                            .replace("\\)", ")")
                            .replace("\\\\", "\\")
                        )
                        meta[field.decode("ascii").lower()] = val
                    except Exception as e:
                        logger.debug(
                            "Error parsing PDF metadata field %s: %s",
                            field,
                            e,
                        )

            # XMP Metadata (T8)
            if b"<x:xmpmeta" in data:
                # Extract simple tags from XMP packet
                xmp_matches = re.findall(b"<dc:([a-zA-Z]+)>([^<]+)</dc:", data)
                for tag, val in xmp_matches:
                    try:
                        meta[tag.decode("utf-8").lower()] = val.decode(
                            "utf-8", errors="ignore"
                        )
                    except Exception as e:
                        logger.debug("Error parsing XMP metadata tag %s: %s", tag, e)

            # Use metadata values to filter text extraction
            meta_values = set(meta.values())

            # --- 2. Extract Strings (Basic Text Extraction) ---
            # PDF strings are ( ... )
            # Regex handles escaped parentheses: \(( (?: [^)\\] | \\. )* )\)
            strings = re.findall(b"\\(((?:[^)\\\\]|\\\\.)*)\\)", data)
            # Decode found strings
            text_parts = []
            for s in strings:
                try:
                    s_decoded = s.decode("utf-8", errors="ignore")
                    # Basic PDF Unescaping
                    s_decoded = (
                        s_decoded.replace("\\(", "(")
                        .replace("\\)", ")")
                        .replace("\\\\", "\\")
                    )

                    # If this string is exactly one of the metadata keys, skip it
                    # (This prevents T8 payloads from leaking into T4 text scan)
                    if s_decoded not in meta_values:
                        text_parts.append(s_decoded)
                except Exception as e:
                    logger.debug("Error decoding PDF string: %s", e)

            text = " ".join(text_parts)

            # --- 2.5 Extract PDF Comments (T4/T8 Injection in Comments) ---
            # Comments start with % and go to end of line
            # We filter out structural comments like %PDF-1.x and %EOF
            raw_comments = re.findall(b"%([^\r\n]*)", data)
            pdf_comments = []
            for c in raw_comments:
                try:
                    c_str = c.decode("utf-8", errors="ignore").strip()
                    if not c_str:
                        continue
                    # Filter structural markers
                    if c_str.startswith("PDF-") or c_str == "EOF":
                        continue
                    # Filter binary-like garbage (high ASCII or too short)
                    if len(c_str) < 3:
                        continue

                    pdf_comments.append(c_str)
                except Exception as e:
                    logger.debug("Error decoding PDF comment: %s", e)

            if pdf_comments:
                meta["pdf_comments"] = pdf_comments

            # --- 3. Hex Blobs (T7 - Embedded Payload) ---
            # Look for large hex strings <AABB...>
            # We want to catch the appended payload <HEX...>
            # Pattern: < followed by many hex chars followed by >
            # We use a threshold of 100 chars to avoid small object refs
            hex_candidates = re.findall(b"<([0-9a-fA-F \t\n\r]{100,})>", data)

            cleaned_blobs = []
            for h in hex_candidates:
                # Remove whitespace
                h_clean = re.sub(b"[ \t\n\r]", b"", h)
                if len(h_clean) > 256:  # 256 chars = 128 bytes
                    # Add to metadata for detector
                    cleaned_blobs.append(h_clean.decode("ascii", errors="ignore"))

            # Also check for /EmbeddedFiles catalog
            if b"/EmbeddedFiles" in data or b"/Ef" in data:
                # It indicates presence. We can add a specialized "blob" or flag.
                # Let's extract names of embedded files if possible
                embedded_names = re.findall(rb"/F \(([^)]+)\)", data)
                if embedded_names:
                    meta["embedded_files"] = [
                        n.decode("utf-8", errors="ignore") for n in embedded_names
                    ]
                    # T7 logic might need to be aware of this key, or we just push a
                    # dummy blob to trigger it?
                    # Better: add a dummy hex blob so "hex_blobs" isn't empty, if we
                    # want to flag it as suspicious?
                    # Or ideally, the detector should check 'embedded_files'.
                    # For now, let's treat presence of EmbeddedFiles as a "blob"
                    # equal to the file signature if we can't extract content easily.
                    pass

            if cleaned_blobs:
                meta["hex_blobs"] = cleaned_blobs

    except Exception as e:
        logger.warning("Fallback PDF parser error", path=path, error=str(e))
    return text, meta


def convert_with_docling(
    source: str, *, max_num_pages: int, max_file_size_bytes: int
) -> Tuple[str, Dict[str, Any]]:
    logger.debug("convert_with_docling called", source=source)
    text = ""
    meta = {}
    docling_success = False

    # 1. Try Docling for High-Quality Text/Table Parsing
    if HAS_DOCLING:
        try:
            conv = _converter()
            result = conv.convert(
                source,
                raises_on_error=True,
                max_num_pages=max_num_pages,
                max_file_size=max_file_size_bytes,
            )
            text = result.document.export_to_markdown()
            meta = result.document.dict()
            docling_success = True
        except Exception as e:
            # Docling failed, proceed to use fallback for text
            logger.debug("Docling conversion failed: %s", e)

    # 2. Run Security Artifact Extraction (Fallback parser logic)
    # We do this ALWAYS to catch T7, T8, T9 specific artifacts that Docling might
    # miss (hex blobs, hidden tags)
    fallback_text, fallback_meta = "", {}
    if source.lower().endswith(".docx"):
        fallback_text, fallback_meta = _fallback_docx(source)
    elif source.lower().endswith(".pdf"):
        fallback_text, fallback_meta = _fallback_pdf(source)

    # 3. Merge Results
    if not docling_success:
        text = fallback_text
        meta = fallback_meta
    else:
        # Merge security artifacts into Docling metadata
        # We prioritize fallback_meta for specific security keys
        for k in ["hex_blobs", "hidden_text", "has_hidden_tags", "comments"]:
            if k in fallback_meta:
                meta[k] = fallback_meta[k]

        # Merge other metadata if missing (e.g. title if Docling missed it)
        for k, v in fallback_meta.items():
            if k not in meta or not meta[k]:
                meta[k] = v

        # CLEANUP: Remove Metadata Payloads from Text (Fixes T8/T4 False Positives)
        # Ensure that values found in metadata (likely T8 payloads) are not present
        # in the body text.
        # This acts as a second layer of defense if Docling extracted them as text.
        exclusion_list = set()
        for k, v in fallback_meta.items():
            # Only filter standard metadata fields, not internal flags
            if k in [
                "title",
                "author",
                "subject",
                "keywords",
                "creator",
                "producer",
                "description",
            ] and isinstance(v, str):
                exclusion_list.add(v.strip())

        for val in exclusion_list:
            if len(val) > 4 and val in text:  # Limit short string removal to avoid FP
                text = text.replace(val, "")

    return text, meta
