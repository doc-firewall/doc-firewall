from __future__ import annotations
import re
import zipfile
from typing import List

from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()



STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]

# ── Hidden content patterns (H1 parity for PPTX) ──────────────────────────
# 1. Near-white text color in DrawingML: <a:srgbClr val="XXXXXX"> where all
#    6 hex digits are E or F — R,G,B ≥ 0xEE = invisible on white slide.
_PPTX_WHITE_COLOR_RE = re.compile(
    rb'<a:srgbClr\s+val="([EF]{6})"', re.IGNORECASE
)
# 2. Tiny font: <a:rPr sz="N"/> where N is in hundredths of a point.
#    sz ≤ 200 = ≤ 2pt (mirrors DOCX H1 threshold).
_PPTX_TINY_FONT_RE = re.compile(rb'<a:rPr\b[^>]*\bsz="(\d{1,3})"')
# 3. Hidden shapes: any element with hidden="1" (p:cNvPr, p:sp, etc.)
_PPTX_HIDDEN_SHAPE_RE = re.compile(rb'\bhidden="1"')
# 4. Off-slide position: <a:off x="N" y="M"/> beyond 2× slide dimensions.
#    Standard slide: 9 144 000 × 6 858 000 EMU.
_PPTX_OFFSLIDE_RE = re.compile(rb'<a:off\s+x="(-?\d+)"\s+y="(-?\d+)"')
_PPTX_OFFSLIDE_X_LIMIT = 9_144_000 * 2
_PPTX_OFFSLIDE_Y_LIMIT = 6_858_000 * 2


def _check_hidden_pptx(content: bytes, filename: str) -> list[tuple[str, str]]:
    """Detect hidden-text techniques in a slide XML bytes blob."""
    hits: list[tuple[str, str]] = []
    m = _PPTX_WHITE_COLOR_RE.search(content)
    if m:
        hits.append(("white_color", f"white text color: #{m.group(1).decode()}"))

    m = _PPTX_TINY_FONT_RE.search(content)
    if m:
        hundredths = int(m.group(1))
        if hundredths <= 200:
            pts = hundredths / 100
            hits.append(("tiny_font", f"font size {pts}pt (≤2pt threshold)"))

    if _PPTX_HIDDEN_SHAPE_RE.search(content):
        hits.append(("hidden_shape", 'shape/element with hidden="1" found'))

    for m in _PPTX_OFFSLIDE_RE.finditer(content):
        x, y = int(m.group(1)), int(m.group(2))
        if abs(x) > _PPTX_OFFSLIDE_X_LIMIT or abs(y) > _PPTX_OFFSLIDE_Y_LIMIT:
            hits.append(("offslide", f"off-slide position: x={x}, y={y} EMU"))
            break

    return hits


def fast_scan_pptx(file_path: str, config: ScanConfig) -> List[Finding]:
    """Fast structural scan of a PPTX (ZIP-based) file."""
    findings: List[Finding] = []

    if not zipfile.is_zipfile(file_path):
        return findings

    with zipfile.ZipFile(file_path, "r") as zf:
        infolist = zf.infolist()
        part_count = len(infolist)
        total_uncompressed = sum(z.file_size for z in infolist)
        total_compressed = sum(z.compress_size for z in infolist)
        overall_ratio = (
            total_uncompressed / total_compressed if total_compressed > 0 else 0
        )

        # 1. DoS / structure checks
        if part_count > config.limits.max_pptx_parts:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many PPTX parts",
                    explain=(
                        f"File contains {part_count} parts "
                        f"(limit {config.limits.max_pptx_parts})."
                    ),
                    evidence={
                        "part_count": part_count,
                        "limit": config.limits.max_pptx_parts,
                    },
                    module="fast_scan.pptx.structure",
                )
            )

        total_mb = total_uncompressed / (1024 * 1024)
        if total_mb > config.limits.max_pptx_total_uncompressed_mb:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="PPTX total uncompressed size too large",
                    explain=(
                        f"Uncompressed size {total_mb:.2f} MB exceeds limit "
                        f"{config.limits.max_pptx_total_uncompressed_mb} MB."
                    ),
                    evidence={"size_mb": total_mb},
                    module="fast_scan.pptx.structure",
                )
            )

        suspicious_parts = 0

        # Slide count sanity check
        slide_count = sum(
            1
            for z in infolist
            if z.filename.startswith("ppt/slides/slide") and z.filename.endswith(".xml")
        )
        if slide_count > config.limits.max_pages:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.MEDIUM,
                    title="Excessive slide count",
                    explain=(
                        f"Presentation contains {slide_count} slides "
                        f"(limit {config.limits.max_pages})."
                    ),
                    evidence={"slide_count": slide_count},
                    module="fast_scan.pptx.structure",
                )
            )

        # 2. Per-part checks
        for z in infolist:
            # Large individual part
            if z.file_size > config.limits.max_pptx_single_part_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Large individual PPTX part",
                        explain=(
                            f"Part {z.filename} is {z.file_size / 1024 / 1024:.2f} MB."
                        ),
                        evidence={
                            "filename": z.filename,
                            "size_mb": z.file_size / 1024 / 1024,
                        },
                        module="fast_scan.pptx.structure",
                    )
                )

            # Compression ratio (zip bomb heuristic)
            ratio = z.file_size / z.compress_size if z.compress_size > 0 else 0
            if (
                ratio > getattr(config.limits, "max_docx_overall_expansion_ratio", 200)
                and z.file_size > 1024 * 1024
            ):
                suspicious_parts += 1

            # VBA macros
            if z.filename.endswith("vbaProject.bin") or "macrosheets" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="PPTX contains VBA macro project",
                        explain=(
                            f"Found '{z.filename}' indicating macro-enabled content. "
                            "Macros are a high-risk active-content vector."
                        ),
                        evidence={"filename": z.filename},
                        module="fast_scan.pptx.macros",
                    )
                )

            # Embedded objects (OLE/media that might carry payloads)
            if z.filename.startswith("ppt/embeddings/"):
                if z.file_size > config.limits.min_embedded_object_size_bytes:
                    evidence = {"filename": z.filename, "size": z.file_size}
                    severity = Severity.MEDIUM
                    title = "PPTX embedded object found"
                    explain = f"Found embedded object '{z.filename}'."
                    try:
                        with zf.open(z.filename) as emf:
                            header = emf.read(4096)
                            if header.startswith(b"\xD0\xCF\x11\xE0"):
                                severity = Severity.HIGH
                                title = "Malicious OLE Payload Signature"
                                explain += " Contains OLE binary header."
                            elif header.startswith(b"MZ"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains DOS MZ header."
                            elif header.startswith(b"\x7FELF"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains ELF binary header."
                    except Exception:
                        pass
                        
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=severity,
                            title=title,
                            explain=explain,
                            evidence=evidence,
                            confidence=0.75,
                            module="fast_scan.pptx.ole",
                        )
                    )

            # External relationships
            if z.filename.endswith(".rels"):
                try:
                    with zf.open(z) as f:
                        rel_content = f.read(512 * 1024)
                        if b'TargetMode="External"' in rel_content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                    severity=Severity.MEDIUM,
                                    title="PPTX external relationship found",
                                    explain=(
                                        f"Found 'TargetMode=\"External\"' in "
                                        f"{z.filename}, indicating external content."
                                    ),
                                    evidence={"filename": z.filename},
                                    confidence=0.65,
                                    module="fast_scan.pptx.rels",
                                )
                            )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # Keyword / stealth char scan on slide XML
            if z.filename.startswith("ppt/slides/slide") and z.filename.endswith(
                ".xml"
            ):
                try:
                    with zf.open(z) as f:
                        content = f.read(1024 * 1024)  # 1 MB cap
                    content_lower = content.lower()
                    for kw in config.prompt_injection_keywords_bytes:
                        if kw in content_lower:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T4_PROMPT_INJECTION,
                                    severity=Severity.MEDIUM,
                                    title="Potential injection keyword (PPTX fast scan)",
                                    explain=(
                                        f"Found keyword '{kw.decode('ascii')}' "
                                        f"in {z.filename}."
                                    ),
                                    evidence={
                                        "keyword": kw.decode("ascii"),
                                        "part": z.filename,
                                    },
                                    module="fast_scan.pptx.keywords",
                                )
                            )
                    for char_bytes, name in STEALTH_CHARS:
                        if char_bytes in content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T3_OBFUSCATION,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious hidden character ({name}) in PPTX",
                                    explain=(
                                        f"Found {name} in {z.filename}, "
                                        "possible stealth injection."
                                    ),
                                    evidence={"char": name, "part": z.filename},
                                    module="fast_scan.pptx.stealth",
                                )
                            )

                    # H1 parity: white text, tiny font, hidden shapes, off-slide
                    for technique, detail in _check_hidden_pptx(content, z.filename):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title=f"PPTX Hidden Text Technique ({technique})",
                                explain=(
                                    f"Detected {detail} in {z.filename}. "
                                    "Hidden text in presentations is a common "
                                    "vector for injecting adversarial content."
                                ),
                                evidence={
                                    "technique": technique,
                                    "detail": detail,
                                    "part": z.filename,
                                },
                                confidence=0.90,
                                module="fast_scan.pptx.hidden_text",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

        # Zip bomb aggregate check
        if suspicious_parts >= 2 or (
            overall_ratio > config.limits.max_docx_overall_expansion_ratio
            and total_mb > 10
        ):
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="PPTX suspicious compression ratio",
                    explain=(
                        "High compression ratio detected, characteristic of zip "
                        "bombs or generated obfuscation."
                    ),
                    evidence={
                        "overall_ratio": round(overall_ratio, 2),
                        "suspicious_parts": suspicious_parts,
                    },
                    module="fast_scan.pptx.structure",
                )
            )

    return findings
