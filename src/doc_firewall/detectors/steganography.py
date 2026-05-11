"""
steganography.py — T7/T8: Steganography and Hidden Payload Detector

Three sub-checks, all gated by ScanConfig.enable_steganography_checks:
  1. Metadata steganography — EXIF/XMP fields with unusually long or
     high-entropy values (Shannon > 6.5 bits/byte or length > 512 chars) → T8
  2. PDF whitespace injection — sequences of 40+ spaces between non-space
     characters in PDF content streams → T7
  3. LSB analysis — chi-square test on image pixel LSBs (requires Pillow;
     gracefully skipped when not installed) → T7

NumPy is a hard dep (already required); Pillow is optional.
"""
from __future__ import annotations

import math
import re
from typing import List

import numpy as np

from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID
from ..report import Finding
from ..logger import get_logger

logger = get_logger()

# Tuning constants
_ENTROPY_HIGH: float = 6.5       # bits/byte — base64 / encrypted payload
_META_LEN_THRESHOLD: int = 512   # chars — suspiciously long field value
_WS_BLOCK_SIZE: int = 40         # consecutive spaces between chars → suspicious
_LSB_P_THRESHOLD: float = 0.05   # chi-square p-value; below → flagged


def _shannon_entropy(data: str | bytes) -> float:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _lsb_chi_pvalue(img_bytes: bytes) -> float:
    """Chi-square p-value for LSB distribution.

    Under natural images the LSBs are close to 50/50.
    LSB steganography makes them highly uniform (p approaches 0.5 — very
    *structured*) or correlated.  We conservatively flag when the chi-square
    statistic is large (p-value small), indicating the distribution departs
    from the natural random baseline.
    """
    arr = np.frombuffer(img_bytes, dtype=np.uint8)
    if len(arr) < 1000:
        return 1.0  # not enough data for a reliable test
    lsbs = arr & 1
    ones = int(np.sum(lsbs))
    zeros = len(lsbs) - ones
    expected = len(lsbs) / 2.0
    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
    return math.exp(-chi2 / 2.0) if chi2 < 700 else 0.0


def _check_metadata(doc: ParsedDocument) -> List[Finding]:
    """Flag metadata fields that are too long or too high-entropy."""
    findings: List[Finding] = []
    if not doc.metadata:
        return findings

    def _walk(d: dict, prefix: str = "") -> None:
        for key, val in d.items():
            field = f"{prefix}{key}"
            if isinstance(val, dict):
                _walk(val, prefix=f"{field}.")
                continue
            if not isinstance(val, (str, bytes)):
                continue
            text = val if isinstance(val, str) else val.decode("utf-8", errors="replace")
            length = len(text)
            if length < 32:
                continue

            if length > _META_LEN_THRESHOLD:
                ent = _shannon_entropy(text)
                findings.append(Finding(
                    threat_id=ThreatID.T8_METADATA_INJECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    title="Suspiciously Long Metadata Field",
                    explain=(
                        f"Metadata field '{field}' is {length} chars "
                        f"(entropy={ent:.2f}). May be a steganographic carrier."
                    ),
                    evidence={
                        "field": field,
                        "length": length,
                        "entropy": round(ent, 3),
                        "malicious_text": text[:250],
                    },
                    module="steganography.metadata",
                ))
                return  # one finding per document at this level

            ent = _shannon_entropy(text)
            if ent > _ENTROPY_HIGH:
                findings.append(Finding(
                    threat_id=ThreatID.T8_METADATA_INJECTION,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    title="High-Entropy Metadata Field",
                    explain=(
                        f"Metadata field '{field}' has entropy {ent:.2f} bits/byte "
                        f"(threshold {_ENTROPY_HIGH}). May contain encoded/encrypted data."
                    ),
                    evidence={
                        "field": field,
                        "entropy": round(ent, 3),
                        "length": length,
                        "malicious_text": text[:250],
                    },
                    module="steganography.metadata",
                ))
                return

    _walk(doc.metadata)
    return findings


def _check_pdf_whitespace(doc: ParsedDocument) -> List[Finding]:
    """Detect whitespace steganography in PDF text (line-based hidden message)."""
    if doc.file_type != "pdf":
        return []
    text = doc.text or ""
    if not text:
        return []

    pattern = re.compile(r"[^\s][ \t]{%d,}[^\s]" % _WS_BLOCK_SIZE)
    matches = list(pattern.finditer(text))
    if not matches:
        return []

    return [Finding(
        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
        severity=Severity.LOW,
        confidence=0.60,
        title="PDF Whitespace Injection Pattern",
        explain=(
            f"Found {len(matches)} sequence(s) of {_WS_BLOCK_SIZE}+ spaces "
            "between text in PDF content. May indicate whitespace steganography."
        ),
        evidence={
            "match_count": len(matches),
            "malicious_text": matches[0].group(0)[:250],
        },
        module="steganography.pdf_whitespace",
    )]


def _check_lsb(doc: ParsedDocument) -> List[Finding]:
    """LSB chi-square test on embedded images (requires Pillow)."""
    try:
        from PIL import Image  # type: ignore
        import io
    except ImportError:
        return []

    image_keys = ("images", "embedded_images", "image_data")
    candidates: list[bytes] = []
    if doc.metadata:
        for key in image_keys:
            val = doc.metadata.get(key)
            if isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, (bytes, bytearray)):
                        candidates.append(bytes(item))
            elif isinstance(val, (bytes, bytearray)):
                candidates.append(bytes(val))

    for idx, img_bytes in enumerate(candidates[:5]):
        try:
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            raw = np.array(img).tobytes()
            p_val = _lsb_chi_pvalue(raw)
            if p_val < _LSB_P_THRESHOLD:
                return [Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.MEDIUM,
                    confidence=round(min(1.0, 1.0 - p_val), 3),
                    title="Suspicious LSB Distribution in Embedded Image",
                    explain=(
                        f"Embedded image #{idx + 1} has a statistically non-random "
                        f"LSB distribution (chi2 p={p_val:.4f}). "
                        "May contain an LSB-steganographic payload."
                    ),
                    evidence={
                        "image_index": idx + 1,
                        "chi2_pvalue": round(p_val, 6),
                        "image_size_bytes": len(img_bytes),
                    },
                    module="steganography.lsb",
                )]
        except Exception:
            continue

    return []


class SteganographyDetector(Detector):
    """Steganography and hidden payload detector (T7/T8).

    Gated by ``ScanConfig.enable_steganography_checks`` (default False).
    Runs three ordered sub-checks; stops after the first finding to avoid
    redundant findings for the same root cause.
    """

    name = "steganography"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_steganography_checks", False):
            return []

        findings = _check_metadata(doc)
        if not findings:
            findings = _check_pdf_whitespace(doc)
        if not findings:
            findings = _check_lsb(doc)
        return findings
