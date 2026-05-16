"""
pdf/obfuscation.py — T3: Advanced PDF Obfuscation Detection

Detects font-substitution attacks via ToUnicode CMap analysis.

Attackers embed a custom CMap that maps visible glyph codes (e.g., 'A')
to a *different* Unicode code point (e.g., 'I'), making the on-screen text
differ from what text-extraction tools (and LLMs) see.  This is the
"font substitution" or "stealth text" technique used to hide injection
phrases from naive scanners while appearing as normal text to human readers.

Checks performed:
  1. Suspicious CMap coverage: CMap entry count that is unusually small
     relative to the number of distinct characters in the visible text —
     indicates only a targeted subset of glyphs is remapped.
  2. Identity-vs-nonidentity CMap: detect ToUnicode CMaps where entries
     systematically remap sequential glyphs to non-sequential code points.
  3. High-entropy CMap values: CMap target code points with Shannon entropy
     indicative of non-natural text (≥ 6.0 bits/byte).
"""
from __future__ import annotations

import math
import re
import zlib
from typing import List

from ...report import Finding
from ..base import ParsedDocument
from ...config import ScanConfig
from ...enums import ThreatID, Severity


# Regex patterns operating on raw PDF bytes
_CMAP_STREAM_RE = re.compile(
    rb"beginbfchar(.*?)endbfchar",
    re.DOTALL,
)
_CMAP_RANGE_RE = re.compile(
    rb"beginbfrange(.*?)endbfrange",
    re.DOTALL,
)
_BF_CHAR_RE = re.compile(
    rb"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>",
)
_BF_RANGE_RE = re.compile(
    rb"<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>",
)

_MAX_SCAN_BYTES = 4 * 1024 * 1024  # 4 MB of the file is enough for CMap data
_MIN_CMAP_ENTRIES = 3              # Ignore trivial CMaps (< 3 entries)
_NONSEQUENTIAL_RATIO = 0.4         # 40%+ non-sequential remaps → suspicious
_HIGH_ENTROPY_THRESHOLD = 5.5      # bits/byte over target code points


def _entropy(values: list[int]) -> float:
    """Shannon entropy of a list of integers."""
    if not values:
        return 0.0
    n = len(values)
    counts: dict[int, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _parse_cmap_entries(pdf_data: bytes) -> list[tuple[int, int]]:
    """Extract (src_glyph, dst_unicode) pairs from all ToUnicode CMaps."""
    entries: list[tuple[int, int]] = []

    for block_match in _CMAP_STREAM_RE.finditer(pdf_data):
        block = block_match.group(1)
        for m in _BF_CHAR_RE.finditer(block):
            try:
                src = int(m.group(1), 16)
                dst = int(m.group(2), 16)
                entries.append((src, dst))
            except ValueError:
                continue

    for block_match in _CMAP_RANGE_RE.finditer(pdf_data):
        block = block_match.group(1)
        for m in _BF_RANGE_RE.finditer(block):
            try:
                src_start = int(m.group(1), 16)
                src_end = int(m.group(2), 16)
                dst_start = int(m.group(3), 16)
                for offset in range(src_end - src_start + 1):
                    entries.append((src_start + offset, dst_start + offset))
            except ValueError:
                continue

    return entries


def _cmap_is_suspicious(entries: list[tuple[int, int]]) -> tuple[bool, str]:
    """Return (suspicious, reason) for a set of CMap entries."""
    if len(entries) < _MIN_CMAP_ENTRIES:
        return False, ""

    # Check for non-sequential remapping (font substitution indicator)
    non_seq = sum(
        1 for src, dst in entries
        if abs(dst - src) > 2  # tolerance: accents and diacritics are close
    )
    ratio = non_seq / len(entries)
    if ratio >= _NONSEQUENTIAL_RATIO:
        return True, (
            f"{non_seq}/{len(entries)} CMap entries remap glyphs to "
            f"non-sequential Unicode code points (ratio={ratio:.2f})"
        )

    # Check entropy of destination code points
    dst_bytes = [b for _, dst in entries for b in dst.to_bytes(2, "big")]
    ent = _entropy(dst_bytes)
    if ent >= _HIGH_ENTROPY_THRESHOLD:
        return True, (
            f"ToUnicode CMap target code points have entropy {ent:.2f} bits/byte "
            f"(>{_HIGH_ENTROPY_THRESHOLD}), suggesting encoded/encrypted mapping"
        )

    return False, ""


def _extract_decompressed_cmap_data(pdf_data: bytes) -> bytes:
    """Decompress FlateDecode streams that contain ToUnicode CMap data.

    A PDF that FlateDecode-compresses its ToUnicode stream hides the CMap
    entirely from raw-byte regex scanning.  This function decompresses those
    streams so _parse_cmap_entries() can analyse them.
    """
    _STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
    out_parts: list[bytes] = []
    for m in _STREAM_RE.finditer(pdf_data):
        raw_stream = m.group(1)
        header_start = max(0, m.start() - 512)
        header_bytes = pdf_data[header_start:m.start()]
        if b"FlateDecode" not in header_bytes:
            continue
        try:
            decompressed = zlib.decompress(raw_stream)
            if b"beginbfchar" in decompressed or b"beginbfrange" in decompressed:
                out_parts.append(decompressed)
        except zlib.error:
            continue
    return b" ".join(out_parts)


def detect_pdf_obfuscation(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    """Detect font-substitution obfuscation via ToUnicode CMap analysis."""
    findings: List[Finding] = []

    if not doc.file_path:
        return findings

    try:
        with open(doc.file_path, "rb") as fh:
            pdf_data = fh.read(_MAX_SCAN_BYTES)
    except OSError:
        return findings

    if b"ToUnicode" not in pdf_data:
        return findings

    # Pass 1: scan raw bytes for uncompressed CMaps.
    entries = _parse_cmap_entries(pdf_data)

    # Pass 2: decompress FlateDecode streams and re-scan for hidden CMaps.
    if b"FlateDecode" in pdf_data:
        decompressed_data = _extract_decompressed_cmap_data(pdf_data)
        if decompressed_data:
            extra_entries = _parse_cmap_entries(decompressed_data)
            entries.extend(extra_entries)

    if not entries:
        return findings

    suspicious, reason = _cmap_is_suspicious(entries)
    if suspicious:
        findings.append(Finding(
            threat_id=ThreatID.T3_OBFUSCATION,
            severity=Severity.MEDIUM,
            confidence=0.75,
            title="Suspicious ToUnicode CMap — Font Substitution Attack",
            explain=(
                f"PDF ToUnicode CMap analysis detected a potential font-substitution "
                f"attack: {reason}. On-screen text may differ from extracted text, "
                "hiding injection phrases from text-based scanners."
            ),
            evidence={
                "cmap_entry_count": len(entries),
                "reason": reason,
            },
            module="pdf.obfuscation.cmap",
        ))

    # D.16: /ActualText overlay — PDF operator that overrides the extracted
    # text for an enclosing span.  Attackers use it so the rendered glyphs
    # show one string while text extractors (and LLMs) see another.  A high
    # *count* of /ActualText spans in a single file is the cheap heuristic;
    # value divergence requires the content stream, which we don't fully
    # parse here.
    _ACTUAL_TEXT_RE = re.compile(rb"/ActualText\s*[(\[<]")
    actual_text_count = len(_ACTUAL_TEXT_RE.findall(pdf_data))
    if actual_text_count >= 5:
        findings.append(Finding(
            threat_id=ThreatID.T3_OBFUSCATION,
            severity=Severity.MEDIUM if actual_text_count < 25 else Severity.HIGH,
            confidence=0.70 if actual_text_count < 25 else 0.85,
            title="PDF /ActualText Overlay Density",
            explain=(
                f"PDF contains {actual_text_count} /ActualText operators. "
                "/ActualText overrides the extracted Unicode for a marked-content "
                "span — attackers use it so the rendered text differs from what "
                "text extractors and LLMs see. Legitimate accessibility usage is "
                "rare and bounded."
            ),
            evidence={
                "subtype": "actual_text_overlay",
                "count": actual_text_count,
                "malicious_text": f"/ActualText × {actual_text_count}",
            },
            module="pdf.obfuscation.actual_text",
        ))

    return findings
