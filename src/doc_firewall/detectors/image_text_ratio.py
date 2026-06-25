"""W4 (0.5.0) — T3: image-based-injection advisory (language-agnostic).

An attacker can hide an instruction by rendering it as an image (a screenshot
of text, text baked into a logo). Without OCR — which is opt-in — that text
is invisible to the scanner. This cheap, no-OCR heuristic surfaces the blind
spot: a document that is **image-heavy with little extractable text** is
flagged for OCR review, regardless of language.

It is an *advisory* (MEDIUM / REVIEW): it does not claim the images are
malicious, only that they were not inspected. It is **suppressed when OCR is
enabled** (the images will be read), so it never double-flags a configured
pipeline. A normal text document with little/no imagery is not flagged.
"""
from __future__ import annotations

import os
import re
import zipfile
from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID, VerdictClass
from ..report import Finding
from .base import Detector

_MITRE = "T1027"
# Trigger only when extractable text is this sparse AND images are present —
# i.e. the document's content is plausibly *in* the images, not the text.
_MIN_TEXT_CHARS = 200
_MIN_IMAGES = 1
_MAX_PDF_READ = 16 * 1024 * 1024

_PDF_IMAGE_RE = re.compile(rb"/Subtype\s*/Image\b")
_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".emf", ".wmf")
_MEDIA_DIRS = ("word/media/", "ppt/media/", "xl/media/", "media/", "pictures/")


def _count_images(path: str, file_type: str) -> int:
    ft = (file_type or "").lower()
    try:
        if ft.startswith("pdf"):
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                blob = f.read(min(size, _MAX_PDF_READ))
            return len(_PDF_IMAGE_RE.findall(blob))
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as zf:
                return sum(
                    1
                    for n in zf.namelist()
                    if n.lower().endswith(_IMG_EXT)
                    and any(d in n.lower() for d in _MEDIA_DIRS)
                )
    except Exception:
        return 0
    return 0


class ImageTextRatioDetector(Detector):
    name = "image_text_ratio"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_image_text_ratio", True):
            return []
        # If OCR is on, the images WILL be inspected — no blind spot to flag.
        if getattr(config, "enable_ocr_injection_scan", False):
            return []

        text_chars = len((doc.text or "").strip())
        if text_chars >= _MIN_TEXT_CHARS:
            return []

        images = _count_images(doc.file_path, doc.file_type)
        if images < _MIN_IMAGES:
            return []

        return [Finding(
            threat_id=ThreatID.T3_OBFUSCATION,
            severity=Severity.MEDIUM,
            title="Image-heavy document with little extractable text",
            explain=(
                f"This document has {images} image(s) but only {text_chars} "
                "characters of extractable text. Instructions hidden in an "
                "image (a screenshot of text, text in a logo) would be "
                "invisible to the scanner because OCR is disabled. Enable OCR "
                "to inspect the image content, or treat the document as "
                "unverified."
            ),
            evidence={
                "subtype": "uninspected_images",
                "image_count": images,
                "extractable_text_chars": text_chars,
                "evidence_unavailable_reason": (
                    "image content was not OCR'd (enable_ocr_injection_scan is "
                    "off); text rendered inside images cannot be read"
                ),
                "debug_steps": [
                    "Enable OCR: set enable_ocr_injection_scan=True and "
                    "`pip install doc-firewall[ml]` (pytesseract + Pillow).",
                    "Or extract and review the embedded images manually.",
                ],
            },
            module=self.name,
            confidence=0.5,
            mitre_technique=_MITRE,
            attack_objective="Hide an instruction in an image to evade text-based scanning",
            verdict_class=VerdictClass.REVIEW,
        )]
