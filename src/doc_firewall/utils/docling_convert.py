from __future__ import annotations

import os
import re
import threading
import time
import zipfile
from typing import Any, Dict, Tuple

from ..logger import get_logger


def _persistent_docling_loop(task_q: Any, result_q: Any, device: str = "cpu") -> None:
    """Long-lived Docling worker: import docling + build the converter (and lazy-
    load its models) ONCE, then convert PDFs streamed over ``task_q``. Module-
    level so multiprocessing 'spawn' can import it in the child.

    Protocol: emits ``("ready", "", {})`` once initialised (or ``("fatal", …)``
    if import/build fails), then one ``("ok"/"err", text, meta)`` per task. A
    ``None`` task is the shutdown sentinel. Replaces the old one-shot worker that
    re-imported docling+torch (~5 s) and rebuilt the converter for *every* PDF.
    """
    os.environ["DOCLING_DISABLE_OCR"] = "1"
    os.environ["RAPIDOCR_DISABLE_AUTO_DOWNLOAD"] = "1"
    os.environ["DOCLING_DEVICE"] = device
    try:
        from docling.datamodel.accelerator_options import AcceleratorOptions
        from docling.datamodel.document import InputFormat
        from docling.datamodel.pipeline_options import PdfPipelineOptions
        from docling.document_converter import DocumentConverter, PdfFormatOption

        pipeline_options = PdfPipelineOptions()
        pipeline_options.do_ocr = False
        pipeline_options.do_table_structure = False
        pipeline_options.table_structure_options.do_cell_matching = False
        pipeline_options.accelerator_options = AcceleratorOptions(device=device)
        conv = DocumentConverter(
            allowed_formats=[InputFormat.PDF],
            format_options={
                InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline_options)
            },
        )
    except Exception as exc:
        try:
            result_q.put(("fatal", str(exc), {}))
        except Exception:
            pass
        return

    try:
        result_q.put(("ready", "", {}))
    except Exception:
        return

    while True:
        try:
            task = task_q.get()
        except Exception:
            return
        if task is None:  # shutdown sentinel
            return
        source, max_num_pages, max_file_size_bytes = task
        try:
            result = conv.convert(
                source,
                raises_on_error=True,
                max_num_pages=max_num_pages,
                max_file_size=max_file_size_bytes,
            )
            text = result.document.export_to_markdown()
            meta = result.document.dict()
            result_q.put(("ok", text, meta))
        except Exception as exc:
            result_q.put(("err", str(exc), {}))


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
    from docling.datamodel.document import InputFormat
    from docling.datamodel.pipeline_options import PdfPipelineOptions
    from docling.document_converter import DocumentConverter, PdfFormatOption

    HAS_DOCLING = True
except ImportError:
    HAS_DOCLING = False

if HAS_DOCLING:
    _cached_converter = None
    _cached_converter_device: str | None = None

    def _converter(device: str = "cpu") -> "DocumentConverter":
        """Lazy-built, device-keyed Docling converter cache.

        The cache key includes the device so changing `docling_device` at
        runtime rebuilds the converter rather than silently reusing one
        constructed with the previous device.
        """
        global _cached_converter, _cached_converter_device
        if _cached_converter is None or _cached_converter_device != device:
            import logging
            logging.getLogger("RapidOCR").setLevel(logging.WARNING)
            try:
                # also silence underlying
                logging.getLogger("rapidocr_onnxruntime").setLevel(logging.WARNING)
            except Exception:
                pass

            from docling.datamodel.accelerator_options import AcceleratorOptions

            pipeline_options = PdfPipelineOptions()
            pipeline_options.do_ocr = False
            pipeline_options.do_table_structure = False
            pipeline_options.table_structure_options.do_cell_matching = False
            pipeline_options.accelerator_options = AcceleratorOptions(device=device)

            # Key must be InputFormat.PDF (enum), not PdfFormatOption (class).
            # Using the wrong key causes the custom option to be silently ignored,
            # leaving do_ocr=True on the default pipeline and triggering the
            # "No OCR engine found" warning on Linux where ocrmac is unavailable.
            # Also restrict allowed_formats to PDF so no other format pipeline
            # (which would default to do_ocr=True) is registered at all.
            _cached_converter = DocumentConverter(
                allowed_formats=[InputFormat.PDF],
                format_options={
                    InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline_options)
                }
            )
            _cached_converter_device = device
        return _cached_converter

    import atexit
    def _cleanup_converter() -> None:
        global _cached_converter
        if _cached_converter is not None:
            _cached_converter = None

    atexit.register(_cleanup_converter)


class _DoclingWorker:
    """Manages one persistent Docling subprocess.

    The old design spawned a fresh subprocess per PDF, which re-imported
    docling+torch (~5 s) and rebuilt the converter every single file — pure
    overhead that dominated bulk-scan time. This keeps one worker alive so that
    cost is paid once. Hang-isolation is preserved: a conversion that exceeds
    the timeout (or a worker that crashes) tears the worker down, and the next
    request transparently respawns a clean one.
    """

    def __init__(self, device: str):
        import multiprocessing as _mp

        self._device = device
        self._ctx = _mp.get_context("spawn")
        self._proc = None
        self._task_q = None
        self._result_q = None
        self._lock = threading.Lock()

    def _start(self, ready_timeout: float = 300.0) -> None:
        import queue as _q

        self._stop()
        self._task_q = self._ctx.Queue()
        self._result_q = self._ctx.Queue()
        self._proc = self._ctx.Process(
            target=_persistent_docling_loop,
            args=(self._task_q, self._result_q, self._device),
            daemon=True,
        )
        self._proc.start()
        try:
            status, _, _ = self._result_q.get(timeout=ready_timeout)
        except _q.Empty:
            self._stop()
            raise RuntimeError("Docling worker did not initialise in time") from None
        if status != "ready":
            self._stop()
            raise RuntimeError(f"Docling worker init failed: {status}")

    def _stop(self) -> None:
        proc = self._proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.join(timeout=3)
            except Exception:
                pass
        for q in (self._task_q, self._result_q):
            if q is not None:
                try:
                    q.close()
                except Exception:
                    pass
        self._proc = None
        self._task_q = None
        self._result_q = None

    def convert(self, source, max_num_pages, max_file_size_bytes, timeout_s):
        """Return ``(status, text, meta)`` — status is ok / err / timeout.
        Serialised: one conversion at a time per worker."""
        import queue as _q

        with self._lock:
            if self._proc is None or not self._proc.is_alive():
                self._start()
            try:
                self._task_q.put((source, max_num_pages, max_file_size_bytes))
            except Exception as exc:
                self._stop()
                return "err", str(exc), {}

            # Poll so a crashed worker is detected within ~1 s instead of
            # blocking for the full (large) timeout.
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                try:
                    return self._result_q.get(timeout=1.0)
                except _q.Empty:
                    if self._proc is None or not self._proc.is_alive():
                        self._stop()
                        return "err", "docling worker exited unexpectedly", {}
            # Exceeded the per-file budget — the worker is wedged (bomb PDF).
            self._stop()
            return "timeout", "", {}


_worker_lock = threading.Lock()
_docling_worker: "_DoclingWorker | None" = None
_docling_worker_device: "str | None" = None


def _get_docling_worker(device: str) -> "_DoclingWorker":
    """Process-wide singleton persistent Docling worker, keyed by device."""
    global _docling_worker, _docling_worker_device
    with _worker_lock:
        if _docling_worker is None or _docling_worker_device != device:
            if _docling_worker is not None:
                _docling_worker._stop()
            _docling_worker = _DoclingWorker(device)
            _docling_worker_device = device
        return _docling_worker


def _shutdown_docling_worker() -> None:
    global _docling_worker
    with _worker_lock:
        if _docling_worker is not None:
            _docling_worker._stop()
            _docling_worker = None


import atexit as _atexit  # noqa: E402

_atexit.register(_shutdown_docling_worker)


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

# Above this control-character density a decoded PDF "string" is binary
# (compressed-stream bytes the ( ) regex matched across), not text.
_FALLBACK_MAX_CONTROL_RATIO = 0.05


def _is_textual(s: str) -> bool:
    """True when ``s`` reads as natural-language text rather than binary.
    Script-agnostic: it counts C0/C1 control characters (which prose of any
    language essentially never contains) — not alphabet membership — so
    Chinese / Arabic / Cyrillic text is kept while compressed-stream bytes are
    rejected."""
    if not s:
        return False
    ctrl = sum(
        1 for c in s
        if (ord(c) < 0x20 and c not in "\t\n\r") or 0x7F <= ord(c) <= 0x9F
    )
    return ctrl / len(s) <= _FALLBACK_MAX_CONTROL_RATIO


# PDF structural keywords that legitimate document prose never contains. The
# `( ... )` text-string regex below over-captures whenever a stray 0x28 byte in
# a binary content stream pairs with a later 0x29: the captured span then holds
# the surrounding object syntax (``endobj``, ``<</Type/Font...>>``, width
# arrays). That span is mostly *printable*, so the C0/C1 control-char gate in
# `_is_textual` passes it — and the raw PDF structure then floods the text
# detectors (T4 BERT/classifier, T3 obfuscation) with false positives on real
# PDFs. These markers identify such an over-capture so it can be dropped.
_PDF_STRUCT_MARKERS = (
    "endobj", "endstream", "stream\r", "stream\n", " 0 obj", " 0 R",
    "/FlateDecode", "/ExtGState", "/ProcSet", "/MediaBox", "/CropBox",
    "/XObject", "/ColorSpace", "/Subtype", "/Resources", "/Contents",
    "/BBox", "/Matrix", "/Type/", "/Type ", "/Font", "<</", "/Pages",
)


# A font /Differences encoding array is a run of /glyphname tokens, e.g.
# "/space/comma/period/A/C/D/...". A URL path ("/a/b") never reaches five such
# tokens back-to-back, so this matches font tables without touching real text.
_GLYPH_NAME_RUN_RE = re.compile(r"(?:/[A-Za-z][A-Za-z0-9]*){5,}")


def _is_pdf_structure_capture(s: str) -> bool:
    """True when a decoded ``( ... )`` string is really an over-capture across
    PDF object syntax rather than a genuine document text-show string."""
    if any(m in s for m in _PDF_STRUCT_MARKERS):
        return True
    # Glyph-width / encoding arrays and xref spans: long runs dominated by
    # digits, spaces and punctuation with almost no letters are not prose.
    if len(s) > 40:
        alpha = sum(1 for c in s if c.isalpha())
        if alpha / len(s) < 0.25:
            return True
    # Font /Differences glyph-name arrays ("/space/comma/period/A/C/D/…").
    if _GLYPH_NAME_RUN_RE.search(s):
        return True
    return False


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

                    # The ( ) regex also matches across compressed content
                    # streams, where stray 0x28/0x29 bytes bracket large spans of
                    # binary (FlateDecode) data. Feeding that undecoded binary to
                    # the text detectors produced a flood of false positives
                    # (T4 classifier, T3 obfuscation, script-mixing) on real
                    # PDFs. Keep only strings that read as natural-language text;
                    # the control-character test is script-agnostic, so genuine
                    # non-Latin text is preserved.
                    if not _is_textual(s_decoded):
                        continue

                    # Drop spans where the ( ) regex ran across PDF object syntax
                    # (endobj / dict / width arrays) — printable, so _is_textual
                    # passes them, but they are structure, not document text.
                    if _is_pdf_structure_capture(s_decoded):
                        continue

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
    source: str,
    *,
    max_num_pages: int,
    max_file_size_bytes: int,
    timeout_s: float = 30.0,
    device: str = "cpu",
) -> Tuple[str, Dict[str, Any]]:
    """Parse a PDF/DOCX via Docling (subprocess-isolated) + fallback regex.

    `device` is forwarded to Docling's AcceleratorOptions. Default "cpu"
    avoids the MPS float64-unsupported error on Apple Silicon (Docling's
    layout model uses float64 ops that MPS rejects). Pass "auto" / "cuda" /
    "mps" / "xpu" to opt back into a GPU device.
    """
    logger.debug("convert_with_docling called", source=source, device=device)
    text = ""
    meta = {}
    docling_success = False

    # 1. Try Docling for High-Quality Text/Table Parsing.
    # Docling's conv.convert() can hang indefinitely on bomb PDFs and cannot be
    # interrupted from a thread (asyncio.wait_for only cancels the future).
    # We isolate it in a subprocess so SIGKILL can terminate it on timeout.
    #
    # The Docling converter is intentionally restricted to InputFormat.PDF
    # (see _converter / _persistent_docling_loop). DOCX is always parsed by
    # _fallback_docx below, never by Docling. Spawning the Docling subprocess
    # for a non-PDF only to have Docling reject the format wastes a process
    # spawn + import and prints Docling's "does not match any allowed format"
    # rejection straight to stderr. Skip it entirely for non-PDF sources.
    is_pdf = source.lower().endswith(".pdf")
    if HAS_DOCLING and is_pdf:
        # Convert via the PERSISTENT Docling worker — it imports docling+torch
        # and builds the converter once, then reuses them across every PDF
        # (the old design re-paid ~5 s of imports per file). Hang-isolation is
        # preserved: on timeout/crash the worker is killed and the next call
        # respawns it; docling_success stays False so the fallback parser runs.
        try:
            worker = _get_docling_worker(device)
            status, result_text, result_meta = worker.convert(
                source, max_num_pages, max_file_size_bytes, timeout_s
            )
        except Exception as exc:
            status, result_text, result_meta = "err", str(exc), {}

        if status == "ok":
            text = result_text
            meta = result_meta
            docling_success = True
        elif status == "timeout":
            logger.warning(
                "Docling conversion timed out — worker reset",
                source=source,
                timeout_s=timeout_s,
            )
        else:
            logger.debug("Docling conversion failed: %s", result_text)

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

        # SECURITY-SCAN TEXT = UNION of Docling's rendered text and the
        # fallback regex extraction.
        #
        # Docling renders layout text, but on minimal / hand-crafted PDFs it
        # silently truncates or skips raw content-stream string literals
        # (observed: a ~1 KB PDF whose content stream holds an EICAR string
        # decoded to only the first ~110 chars, dropping the payload). The
        # previous logic only promoted the fallback text when Docling
        # returned *empty* text, so a truncated-but-non-empty Docling result
        # caused payloads (EICAR / macro indicators / Base64) to be invisible
        # to every detector — a systemic false-negative on PDFs. `_fallback_pdf`'s
        # regex captures those raw string literals. For a security scanner,
        # recall dominates, so scan both: append the fallback text whenever it
        # carries content Docling did not fully capture.
        fb = fallback_text.strip()
        if fb and (not text.strip() or len(fb) > len(text.strip())):
            text = (text + "\n" + fallback_text) if text.strip() else fallback_text

        # CLEANUP: Remove Metadata Payloads from Text (Fixes T8/T4 False Positives)
        # Ensure that values found in metadata (likely T8 payloads) are not present
        # in the body text. Applied AFTER the union so it covers the combined
        # text. This acts as a second layer of defense if Docling or the
        # fallback extracted them as body text.
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
