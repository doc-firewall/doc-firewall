from __future__ import annotations

import os

from ...config import ScanConfig
from ...logger import get_logger
from ...utils.docling_convert import convert_with_docling
from ...utils.pdf_decrypt import is_pdf_encrypted, try_decrypt_pdf
from ..base import ParsedDocument
from .hidden_text_extract import extract_hidden_pdf_text

logger = get_logger()


def parse_pdf(path: str, config: ScanConfig) -> ParsedDocument:
    # W6 (0.5.0): if the PDF is encrypted, try to decrypt it to a temp file
    # so the deep scan reads the real content instead of a blind spot. The
    # common empty-user-password (permissions-only) case needs no password;
    # pdf_passwords covers real password protection. No-op without pikepdf.
    scan_path = path
    decrypted_tmp: str | None = None
    decrypt_method: str | None = None
    decrypt_reason: str | None = None
    if getattr(config, "enable_pdf_decryption", True) and is_pdf_encrypted(path):
        decrypted_tmp, info = try_decrypt_pdf(
            path, getattr(config, "pdf_passwords", [])
        )
        if decrypted_tmp:
            scan_path = decrypted_tmp
            decrypt_method = info
        else:
            decrypt_reason = info

    try:
        md, d = convert_with_docling(
            scan_path,
            max_num_pages=config.limits.max_pages,
            max_file_size_bytes=config.limits.max_mb * 1024 * 1024,
            timeout_s=float(config.limits.docling_subprocess_timeout_s),
            device=config.limits.docling_device,
        )
        # d is the merged metadata
        # Map pdf_comments into standard comments key for unified detector processing
        if "pdf_comments" in d and "comments" not in d:
            d["comments"] = d["pdf_comments"]

        if decrypt_method:
            # Signals to the scanner that the encrypted content WAS read, so
            # the blind-spot finding can be downgraded.
            d["pdf_decrypted"] = decrypt_method
        elif decrypt_reason:
            d["pdf_decrypt_failed"] = decrypt_reason

        # W4.1 (0.5.0): surface text from non-rendered PDF surfaces — annotation
        # /Contents, form /V, outline /Title, and objects packed in compressed
        # /ObjStm streams — that Docling's rendered-text extraction misses.
        # Stored as a list metadata value so the metadata-walking detectors
        # (prompt-injection-in-metadata, multilingual, script-mixing) scan it.
        try:
            cap = config.limits.max_pdf_bytes_scan_mb * 1024 * 1024
            size = os.path.getsize(scan_path)
            with open(scan_path, "rb") as f:
                blob = f.read(min(size, cap))
            hidden_obj_text = extract_hidden_pdf_text(blob)
            if hidden_obj_text:
                d["_pdf_object_text"] = hidden_obj_text
        except Exception as e:
            logger.debug("PDF hidden-object text extraction failed: %s", e)

        return ParsedDocument(
            file_path=path,
            file_type="pdf",
            text=md,
            metadata=d,
            pdf={"structure": d.get("structure")},
        )
    finally:
        # The decrypted plaintext temp must never outlive the scan.
        if decrypted_tmp:
            try:
                os.remove(decrypted_tmp)
            except OSError:
                pass
