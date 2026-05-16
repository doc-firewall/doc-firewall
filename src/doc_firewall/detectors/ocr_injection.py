"""B.6 + E.3 — OCR-based prompt injection detection in embedded images.

Extracts images from:
  • DOCX / PPTX / XLSX ZIP archives (word/media/, ppt/media/, xl/media/)
  • ODF archives (Pictures/)
  • PDF content streams via PyMuPDF page.get_images()
  • SVG inline <image href="data:..."/> (skipped — TODO)

For each extracted image:
  • OCR via pytesseract → T4 keyword scan
  • E.3: QR-code decode via pyzbar → T10 / T7 (URLs / data: URIs / IPs in
    QR codes are sent through the indirect-injection pipeline)

Gating:
  • `enable_ocr_injection_scan` (default False) — turns on OCR
  • `enable_qr_decode` (default False) — turns on QR decoding

Optional dependencies (silently skipped when absent):
  • pytesseract + Pillow
  • PyMuPDF (`pymupdf` / `fitz`) — for PDF image extraction
  • pyzbar — for QR / barcode decoding
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from typing import List

from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()

_IMAGE_EXTS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
})
_MEDIA_PREFIXES: tuple[str, ...] = (
    "word/media/",
    "ppt/media/",
    "xl/media/",
    "Pictures/",        # E.2 ODF
)
_MAX_IMAGE_BYTES = 5 * 1024 * 1024
_MAX_IMAGES_PER_DOC = 12   # PDF-extracted images count against this budget

# E.3: QR/barcode URL heuristics
_URL_RE = re.compile(r"https?://[^\s'\"<>]{4,}", re.IGNORECASE)
_DATA_URI_RE = re.compile(r"data:[a-z]+/[a-z0-9.+-]+", re.IGNORECASE)
_BITCOIN_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")


def _scan_image_bytes(
    raw_bytes: bytes,
    source: str,
    keywords: list[str],
    config: ScanConfig,
) -> list[Finding]:
    """OCR + QR decode for one image's raw bytes. Returns 0–2 findings."""
    findings: List[Finding] = []

    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        return findings

    try:
        img = Image.open(io.BytesIO(raw_bytes))
    except Exception:
        return findings

    # ── OCR pass ─────────────────────────────────────────────────────────
    if getattr(config, "enable_ocr_injection_scan", False):
        try:
            ocr_text = pytesseract.image_to_string(img)
        except Exception as exc:
            logger.debug("OCR failed for %s: %s", source, exc)
            ocr_text = ""
        ocr_lower = ocr_text.lower()
        matched = next((kw for kw in keywords if kw in ocr_lower), None)
        if matched:
            snippet = ocr_text[:250].replace("\n", " ")
            findings.append(Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                title="Prompt Injection in Embedded Image (OCR)",
                explain=(
                    f"OCR scan of embedded image '{source}' detected a "
                    "prompt injection phrase. Multimodal LLMs that process "
                    "embedded images are vulnerable to this attack vector."
                ),
                evidence={
                    "subtype": "ocr_embedded_image",
                    "source": "ocr_embedded_image",
                    "image": source,
                    "matched_phrase": matched,
                    "snippet": snippet,
                    "malicious_text": snippet,
                },
                module="ocr_injection",
                confidence=0.7,
                mitre_technique="T1027",
                attack_objective=(
                    "Deliver injection payload via embedded image to evade "
                    "text-layer scanning; target multimodal LLM agents."
                ),
            ))

    # ── E.3: QR / barcode decode ────────────────────────────────────────
    if getattr(config, "enable_qr_decode", False):
        try:
            from pyzbar.pyzbar import decode as _zb_decode
        except ImportError:
            return findings
        try:
            decoded_objs = _zb_decode(img)
        except Exception as exc:
            logger.debug("QR decode failed for %s: %s", source, exc)
            return findings

        for d in decoded_objs:
            try:
                payload = d.data.decode("utf-8", errors="replace")
            except Exception:
                continue
            if not payload:
                continue
            findings.extend(_qr_payload_findings(payload, source, keywords))

    return findings


def _qr_payload_findings(payload: str, source: str, keywords: list[str]) -> list[Finding]:
    """Classify a decoded QR / barcode payload and emit findings."""
    out: list[Finding] = []
    payload_l = payload.lower()

    # Direct injection text in the QR payload itself
    matched_kw = next((kw for kw in keywords if kw in payload_l), None)
    if matched_kw:
        out.append(Finding(
            threat_id=ThreatID.T4_PROMPT_INJECTION,
            severity=Severity.HIGH,
            title="Prompt Injection in QR Code Payload",
            explain=(
                f"QR code in '{source}' decodes to text containing an "
                f"injection phrase ('{matched_kw}'). QR codes are routinely "
                "scanned by mobile users and increasingly fed into multi-"
                "modal LLM pipelines — both treat the decoded text as user "
                "intent."
            ),
            evidence={
                "subtype": "qr_injection",
                "source": source,
                "matched_phrase": matched_kw,
                "malicious_text": payload[:250],
            },
            module="ocr_injection",
            confidence=0.85,
            mitre_technique="T1204.002",
            attack_objective="Quishing — deliver injection via QR code payload",
        ))

    # URL in QR payload — quishing carrier
    url_m = _URL_RE.search(payload)
    if url_m:
        # Single URL alone is informational; combined with injection text → HIGH
        sev = Severity.HIGH if matched_kw else Severity.MEDIUM
        out.append(Finding(
            threat_id=ThreatID.T10_INDIRECT_INJECTION,
            severity=sev,
            title="URL in QR Code (Quishing Indicator)",
            explain=(
                f"QR code in '{source}' encodes a URL "
                f"('{url_m.group()[:80]}'). Mobile and multimodal-LLM "
                "users follow QR-encoded URLs implicitly, making this a "
                "preferred indirect-injection / phishing carrier."
            ),
            evidence={
                "subtype": "qr_url",
                "source": source,
                "url": url_m.group()[:200],
                "malicious_text": url_m.group()[:200],
            },
            module="ocr_injection",
            confidence=0.75 if not matched_kw else 0.85,
            mitre_technique="T1204.002",
            attack_objective="Quishing — redirect victim to attacker-controlled URL via QR",
        ))

    # data: URI in QR payload
    if _DATA_URI_RE.search(payload):
        out.append(Finding(
            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
            severity=Severity.HIGH,
            title="data: URI in QR Code Payload",
            explain=(
                f"QR code in '{source}' decodes to a data: URI — a known "
                "carrier for embedded executable payloads and HTML smuggling."
            ),
            evidence={
                "subtype": "qr_data_uri",
                "source": source,
                "malicious_text": payload[:250],
            },
            module="ocr_injection",
            confidence=0.85,
        ))

    # Cryptocurrency address in QR (often used in extortion / BEC)
    if _BITCOIN_RE.search(payload):
        out.append(Finding(
            threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
            severity=Severity.MEDIUM,
            title="Cryptocurrency Wallet Address in QR Code",
            explain=(
                f"QR code in '{source}' encodes a Bitcoin address. Crypto "
                "QR codes are a hallmark of BEC / extortion / ransom notes."
            ),
            evidence={
                "subtype": "qr_crypto_address",
                "source": source,
                "malicious_text": payload[:120],
            },
            module="ocr_injection",
            confidence=0.70,
        ))

    return out


def _iter_pdf_images(file_path: str, max_images: int) -> list[tuple[str, bytes]]:
    """E.3: extract embedded images from a PDF via PyMuPDF.

    Returns a list of (source_label, image_bytes) tuples. Empty if PyMuPDF
    is not installed or the file isn't a PDF.
    """
    out: list[tuple[str, bytes]] = []
    try:
        import fitz  # PyMuPDF
    except ImportError:
        logger.debug("PyMuPDF not installed; PDF image extraction skipped")
        return out

    try:
        doc = fitz.open(file_path)
    except Exception as exc:
        logger.debug("PyMuPDF open failed: %s", exc)
        return out

    try:
        for page_idx, page in enumerate(doc):
            if len(out) >= max_images:
                break
            for img_info in page.get_images(full=True):
                if len(out) >= max_images:
                    break
                xref = img_info[0]
                try:
                    img_data = doc.extract_image(xref)
                except Exception:
                    continue
                if not img_data or "image" not in img_data:
                    continue
                img_bytes = img_data["image"]
                if len(img_bytes) > _MAX_IMAGE_BYTES:
                    continue
                out.append((f"pdf:page{page_idx + 1}:xref{xref}", img_bytes))
    finally:
        try:
            doc.close()
        except Exception:
            pass
    return out


class OCRInjectionDetector(Detector):
    name = "ocr_injection"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not (
            getattr(config, "enable_ocr_injection_scan", False)
            or getattr(config, "enable_qr_decode", False)
        ):
            return []

        try:
            import pytesseract  # noqa: F401
            from PIL import Image  # noqa: F401
        except ImportError:
            logger.debug("pytesseract / Pillow missing; OCR scan skipped")
            return []

        if not doc.file_path or not os.path.isfile(doc.file_path):
            return []

        keywords = [
            kw.decode("utf-8", errors="ignore").lower()
            for kw in config.prompt_injection_keywords_bytes
        ]

        findings: List[Finding] = []
        images_seen = 0

        # ── Path A: ZIP-based formats (DOCX/PPTX/XLSX/ODF) ──────────────
        if zipfile.is_zipfile(doc.file_path):
            try:
                with zipfile.ZipFile(doc.file_path, "r") as zf:
                    for name in zf.namelist():
                        if images_seen >= _MAX_IMAGES_PER_DOC:
                            break
                        ext = os.path.splitext(name.lower())[1]
                        if ext not in _IMAGE_EXTS:
                            continue
                        if not any(name.startswith(p) for p in _MEDIA_PREFIXES):
                            continue
                        zi = zf.getinfo(name)
                        if zi.file_size > _MAX_IMAGE_BYTES:
                            continue
                        try:
                            raw = zf.read(name)
                        except Exception:
                            continue
                        images_seen += 1
                        findings.extend(_scan_image_bytes(raw, name, keywords, config))
            except Exception as exc:
                logger.debug("OCRInjectionDetector ZIP path: %s", exc)

        # ── Path B: PDF image extraction via PyMuPDF (E.3) ──────────────
        if doc.file_type == "pdf" and images_seen < _MAX_IMAGES_PER_DOC:
            pdf_images = _iter_pdf_images(
                doc.file_path, _MAX_IMAGES_PER_DOC - images_seen,
            )
            for label, raw in pdf_images:
                findings.extend(_scan_image_bytes(raw, label, keywords, config))
                images_seen += 1

        return findings
