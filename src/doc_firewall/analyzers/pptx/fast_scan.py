from __future__ import annotations
import zipfile
from typing import List

from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()


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
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.MEDIUM,
                            title="PPTX embedded object found",
                            explain=f"Found embedded object '{z.filename}'.",
                            evidence={"filename": z.filename, "size": z.file_size},
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
