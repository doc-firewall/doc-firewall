"""B.6 — OCR-based prompt injection detection in embedded images.

Extracts images from DOCX/PPTX/XLSX ZIP archives (word/media/, ppt/media/,
xl/media/), runs pytesseract OCR on each, and scans the extracted text for
T4 prompt injection phrases.

Gated on ScanConfig.enable_ocr_injection_scan (default False) because OCR
adds 200–2000 ms per image depending on resolution. Enable it when the
deployment processes documents that may carry injection text in screenshots
or images (e.g. multimodal RAG pipelines).

Requires: pytesseract, Pillow (both optional; missing → silently skipped).
"""
from __future__ import annotations

import io
import os
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
)
_MAX_IMAGE_BYTES = 5 * 1024 * 1024   # skip images > 5 MB (OCR too slow)
_MAX_IMAGES_PER_DOC = 10              # cap total OCR calls per document


class OCRInjectionDetector(Detector):
    name = "ocr_injection"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_ocr_injection_scan", False):
            return []

        try:
            import pytesseract
            from PIL import Image
        except ImportError:
            logger.debug("pytesseract or Pillow not installed; OCR injection scan skipped")
            return []

        if not doc.file_path or not os.path.isfile(doc.file_path):
            return []

        if not zipfile.is_zipfile(doc.file_path):
            return []

        # Build lowercase keyword list once
        keywords = [
            kw.decode("utf-8", errors="ignore").lower()
            for kw in config.prompt_injection_keywords_bytes
        ]

        findings: List[Finding] = []
        images_scanned = 0

        try:
            with zipfile.ZipFile(doc.file_path, "r") as zf:
                for name in zf.namelist():
                    if images_scanned >= _MAX_IMAGES_PER_DOC:
                        break

                    ext = os.path.splitext(name.lower())[1]
                    if ext not in _IMAGE_EXTS:
                        continue
                    if not any(name.startswith(p) for p in _MEDIA_PREFIXES):
                        continue

                    zi = zf.getinfo(name)
                    if zi.file_size > _MAX_IMAGE_BYTES:
                        logger.debug("OCR: skipping large image %s (%d bytes)", name, zi.file_size)
                        continue

                    try:
                        raw = zf.read(name)
                        img = Image.open(io.BytesIO(raw))
                        ocr_text = pytesseract.image_to_string(img)
                    except Exception as exc:
                        logger.debug("OCR failed for %s: %s", name, exc)
                        continue

                    images_scanned += 1
                    ocr_lower = ocr_text.lower()

                    matched = next((kw for kw in keywords if kw in ocr_lower), None)
                    if matched:
                        snippet = ocr_text[:250].replace("\n", " ")
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T4_PROMPT_INJECTION,
                                severity=Severity.MEDIUM,
                                title="Prompt Injection in Embedded Image (OCR)",
                                explain=(
                                    f"OCR scan of embedded image '{name}' detected a "
                                    "prompt injection phrase. Multimodal LLMs that process "
                                    "embedded images are vulnerable to this attack vector."
                                ),
                                evidence={
                                    "source": "ocr_embedded_image",
                                    "image": name,
                                    "matched_phrase": matched,
                                    "snippet": snippet,
                                    "malicious_text": snippet,
                                },
                                module=self.name,
                                confidence=0.7,
                                mitre_technique="T1027",
                                attack_objective=(
                                    "Deliver injection payload via embedded image to evade "
                                    "text-layer scanning; target multimodal LLM agents."
                                ),
                            )
                        )

        except Exception as exc:
            logger.debug("OCRInjectionDetector error: %s", exc)

        return findings
