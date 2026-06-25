"""W3 (0.5.0) — PDF sanitizer (pikepdf-gated).

Removes the active-content and metadata attack surface from a PDF and writes
a cleaned copy: document and page open/additional actions, the document-level
JavaScript name tree, Launch/SubmitForm actions on links, embedded files,
and the /Info + XMP metadata. Visible page content is untouched.

Requires the optional ``pikepdf`` (``pip install doc-firewall[crypto]``);
without it PDF sanitization returns ``sanitized=False`` so the caller falls
back to BLOCK. pikepdf also decrypts permissions-encrypted PDFs in passing.
"""
from __future__ import annotations

from typing import Any, List, Optional

from ..sanitize import (
    Removal,
    SanitizationResult,
    _resolve_out,
    category_enabled,
)


def _pikepdf():
    try:
        import pikepdf  # type: ignore
        return pikepdf
    except Exception:
        return None


def sanitize_pdf(
    path: str, config: Any = None, output_path: Optional[str] = None
) -> SanitizationResult:
    pike = _pikepdf()
    if pike is None:
        return SanitizationResult(
            input_path=path, file_type="pdf", sanitized=False,
            reason="PDF sanitization needs pikepdf (pip install doc-firewall[crypto])",
        )

    removed: List[Removal] = []
    do_active = category_enabled("active_content", config)
    do_meta = category_enabled("metadata", config)
    do_embedded = category_enabled("embedded_file", config)
    passwords = [""] + list(getattr(config, "pdf_passwords", []) or []) if config else [""]

    pdf = None
    for pw in passwords:
        try:
            pdf = pike.open(path, password=pw, allow_overwriting_input=False)
            break
        except pike.PasswordError:
            continue
        except Exception:
            break
    if pdf is None:
        return SanitizationResult(
            input_path=path, file_type="pdf", sanitized=False,
            reason="could not open PDF (encrypted without a known password, or malformed)",
        )

    try:
        root = pdf.Root

        if do_active:
            # Document-level open / additional actions.
            for key in ("/OpenAction", "/AA"):
                if key in root:
                    del root[key]
                    removed.append(Removal(
                        kind="active_content", detail=f"removed document {key}",
                        location="/Root",
                    ))

            # Document-level JavaScript name tree.
            try:
                names = root.get("/Names")
                if names is not None and "/JavaScript" in names:
                    del names["/JavaScript"]
                    removed.append(Removal(
                        kind="active_content", detail="removed document JavaScript name tree",
                        location="/Root/Names",
                    ))
            except Exception:
                pass

            # Per-page and per-annotation actions.
            for pi, page in enumerate(pdf.pages):
                for key in ("/AA", "/OpenAction"):
                    if key in page:
                        del page[key]
                        removed.append(Removal(
                            kind="active_content", detail=f"removed page {key}",
                            location=f"page {pi}",
                        ))
                annots = page.get("/Annots")
                if annots is None:
                    continue
                for an in list(annots):
                    try:
                        if "/A" in an or "/AA" in an:
                            an.pop("/A", None)
                            an.pop("/AA", None)
                            removed.append(Removal(
                                kind="active_content",
                                detail="removed annotation action",
                                location=f"page {pi}",
                            ))
                    except Exception:
                        continue

            # AcroForm-level XFA.
            try:
                acro = root.get("/AcroForm")
                if acro is not None and "/XFA" in acro:
                    del acro["/XFA"]
                    removed.append(Removal(
                        kind="active_content", detail="removed AcroForm /XFA",
                        location="/Root/AcroForm",
                    ))
            except Exception:
                pass

        if do_embedded:
            try:
                names = root.get("/Names")
                if names is not None and "/EmbeddedFiles" in names:
                    del names["/EmbeddedFiles"]
                    removed.append(Removal(
                        kind="embedded_file", detail="removed embedded-files name tree",
                        location="/Root/Names",
                    ))
            except Exception:
                pass

        if do_meta:
            # Metadata — /Info dictionary and XMP stream.
            try:
                with pdf.open_metadata(set_pikepdf_as_editor=False) as md:
                    if len(md) > 0:
                        removed.append(Removal(
                            kind="metadata", detail="cleared XMP metadata",
                        ))
                        md.clear()
            except Exception:
                pass
            if "/Info" in pdf.trailer:
                try:
                    del pdf.trailer["/Info"]
                    removed.append(Removal(
                        kind="metadata", detail="removed /Info metadata dictionary",
                    ))
                except Exception:
                    pass

        out_path = _resolve_out(".pdf", output_path)
        pdf.save(out_path)
        return SanitizationResult(
            input_path=path, file_type="pdf", sanitized=True,
            output_path=out_path, removed=removed,
        )
    finally:
        try:
            pdf.close()
        except Exception:
            pass
