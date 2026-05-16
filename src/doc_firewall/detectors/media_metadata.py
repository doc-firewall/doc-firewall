"""E.5 — Embedded audio/video metadata scanner.

PowerPoint and Word can embed `.mp3` / `.mp4` / `.wav` / `.m4a` files under
`ppt/media/` / `word/media/`. These containers carry text metadata fields
(ID3 tags for MP3, MP4 atom strings, RIFF INFO tags) that LLM document
loaders increasingly extract. Injections placed in those fields bypass the
body-text scan completely.

This detector reads small text fragments from each embedded media file's
metadata region and runs them through the T4 + T8 keyword check. It does
NOT parse audio/video content — only the metadata header at the start of
each file.

Pure stdlib + zipfile. Uses `mutagen` when installed for proper parsing
(better recall on MP4 / FLAC); falls back to a byte-scan otherwise.
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


_MEDIA_EXTS: frozenset[str] = frozenset({
    ".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".aiff", ".aac",
    ".ogg", ".flac", ".mov",
})
_MEDIA_PREFIXES: tuple[str, ...] = (
    "word/media/",
    "ppt/media/",
    "xl/media/",
    "Pictures/",
)
_MAX_MEDIA_BYTES = 4 * 1024 * 1024
_MAX_FILES_PER_DOC = 8


def _extract_text_fragments_fallback(data: bytes) -> list[str]:
    """Heuristic: pull printable ASCII / Latin-1 runs ≥ 12 chars from the
    first 256 KB of `data`. Catches ID3 TIT2/TPE1/COMM frames, MP4 ©nam /
    ©cmt atoms, RIFF INFO tags, FLAC Vorbis comments — all stored as
    plain-text-or-UTF-8 substrings within a binary header."""
    sample = data[: 256 * 1024]
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7E]{12,}|[\xC2-\xF4][\x80-\xBF]{11,}", sample):
        try:
            out.append(m.group(0).decode("latin-1", errors="replace"))
        except Exception:
            continue
    return out


def _extract_text_fragments_mutagen(data: bytes, filename: str) -> list[str]:
    """Use mutagen to extract tag strings when installed."""
    try:
        import mutagen
    except ImportError:
        return []
    try:
        f = mutagen.File(io.BytesIO(data), easy=True)
    except Exception:
        return []
    if f is None:
        return []
    out: list[str] = []
    try:
        for key, val in (f.tags or {}).items():
            if isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v:
                        out.append(v)
            elif isinstance(val, str):
                out.append(val)
    except Exception:
        pass
    return out


def _scan_fragments(
    fragments: list[str],
    keywords: list[str],
    source: str,
) -> list[Finding]:
    findings: List[Finding] = []
    for frag in fragments:
        lower = frag.lower()
        # T4: known injection phrase
        kw = next((k for k in keywords if k in lower), None)
        if kw:
            findings.append(Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                title="Prompt Injection in Embedded Media Metadata",
                explain=(
                    f"Injection keyword '{kw}' found in metadata of embedded "
                    f"media file '{source}'. ID3 / MP4 atom / RIFF INFO tags "
                    "are extracted by LLM document loaders but bypass the "
                    "body-text scan."
                ),
                evidence={
                    "subtype": "media_metadata_injection",
                    "source": source,
                    "matched_phrase": kw,
                    "snippet": frag[:200],
                    "malicious_text": frag[:200],
                },
                module="media_metadata",
                confidence=0.75,
                mitre_technique="T1566",
            ))
            return findings  # one finding per file is enough
        # T8: excessive length / suspicious content in metadata
        if len(frag) > 2000:
            findings.append(Finding(
                threat_id=ThreatID.T8_METADATA_INJECTION,
                severity=Severity.MEDIUM,
                title="Excessive Metadata in Embedded Media",
                explain=(
                    f"Embedded media file '{source}' carries a "
                    f"{len(frag)}-char metadata field. Oversized tags are a "
                    "DoS / data-exfiltration vector in media containers."
                ),
                evidence={
                    "subtype": "media_metadata_oversize",
                    "source": source,
                    "length": len(frag),
                    "snippet": frag[:200],
                    "malicious_text": frag[:200],
                },
                module="media_metadata",
                confidence=0.65,
            ))
            return findings
    return findings


class MediaMetadataDetector(Detector):
    """E.5 — scan ID3 / MP4 / RIFF / Vorbis tags in embedded audio/video."""

    name = "media_metadata"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_media_metadata_scan", True):
            return []
        if not doc.file_path or not os.path.isfile(doc.file_path):
            return []
        if not zipfile.is_zipfile(doc.file_path):
            return []

        keywords = [
            kw.decode("utf-8", errors="ignore").lower()
            for kw in config.prompt_injection_keywords_bytes
        ]
        findings: List[Finding] = []
        files_scanned = 0

        try:
            with zipfile.ZipFile(doc.file_path, "r") as zf:
                for name in zf.namelist():
                    if files_scanned >= _MAX_FILES_PER_DOC:
                        break
                    ext = os.path.splitext(name.lower())[1]
                    if ext not in _MEDIA_EXTS:
                        continue
                    if not any(name.startswith(p) for p in _MEDIA_PREFIXES):
                        continue
                    zi = zf.getinfo(name)
                    if zi.file_size > _MAX_MEDIA_BYTES:
                        continue
                    try:
                        raw = zf.read(name)
                    except Exception:
                        continue
                    files_scanned += 1

                    # Prefer mutagen when available
                    fragments = _extract_text_fragments_mutagen(raw, name)
                    if not fragments:
                        fragments = _extract_text_fragments_fallback(raw)

                    findings.extend(_scan_fragments(fragments, keywords, name))
        except Exception as exc:
            logger.debug("MediaMetadataDetector error: %s", exc)

        return findings
