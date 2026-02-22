from __future__ import annotations
import zipfile
from typing import List
from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()

PROMPT_INJECTION_KEYWORDS = [
    b"ignore previous",
    b"system instruction",
    b"system prompt",
    b"reveal your",
    b"ignore the above",
    b"new instruction",
    b"hiring manager",
    b"return a score",
    b"you are now",
    b"ignore all previous",
    b"rank this candidate",
    b"ignore instructions",
    b"rank this resume",
    b"forget all previous",
    b"prioritize this candidate",
    # Expanded for higher recall
    b"reveal these",
    b"do not reveal",
    b"output only",
    b"system role",
    b"instruction override",
]

STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]


def fast_scan_docx(file_path: str, config: ScanConfig) -> List[Finding]:
    findings = []

    # Removed global try-except
    if not zipfile.is_zipfile(file_path):
        return findings

    with zipfile.ZipFile(file_path, "r") as zf:
        infolist = zf.infolist()

        part_count = len(infolist)
        total_uncompressed = sum(z.file_size for z in infolist)
        total_compressed = sum(z.compress_size for z in infolist)
        overall_ratio = (
            (total_uncompressed / total_compressed) if total_compressed > 0 else 0
        )

        # 1. Zip Bomb / DoS Checks
        if part_count > config.limits.max_docx_parts:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many DOCX parts",
                    explain=(
                        f"File contains {part_count} parts (limit "
                        f"{config.limits.max_docx_parts})."
                    ),
                    evidence={
                        "part_count": part_count,
                        "limit": config.limits.max_docx_parts,
                    },
                    module="fast_scan.docx.structure",
                )
            )

        total_mb = total_uncompressed / (1024 * 1024)
        if total_mb > config.limits.max_docx_total_uncompressed_mb:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Total uncompressed size too large",
                    explain=(
                        f"Uncompressed size {total_mb:.2f} MB exceeds limit "
                        f"{config.limits.max_docx_total_uncompressed_mb} MB."
                    ),
                    evidence={"size_mb": total_mb},
                    module="fast_scan.docx.structure",
                )
            )

        suspicious_parts = 0

        # 2. Content Checks (VBA, Embeddings, Keywords)
        # We only check 'word/document.xml' for keywords to save time

        for z in infolist:
            # Zip Bomb heuristic
            if z.file_size > config.limits.max_docx_single_part_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Large individual XML part",
                        explain=(
                            f"Part {z.filename} is "
                            f"{z.file_size / 1024 / 1024:.2f} MB."
                        ),
                        evidence={
                            "filename": z.filename,
                            "size_mb": z.file_size / 1024 / 1024,
                        },
                        module="fast_scan.docx.structure",
                    )
                )

            ratio = z.file_size / z.compress_size if z.compress_size > 0 else 0
            if ratio > 500 and z.file_size > 1024 * 1024:
                suspicious_parts += 1

            # Macros
            if z.filename.endswith("vbaProject.bin") or "macrosheets" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="Macro/VBA Content Found",
                        explain=(
                            f"Found suspicious file '{z.filename}' "
                            "indicating macros."
                        ),
                        evidence={"filename": z.filename},
                        module="fast_scan.docx.macros",
                    )
                )

            # Embeddings
            if "word/embeddings/" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.MEDIUM,
                        title="Embedded Object Found",
                        explain=f"Found embedded object '{z.filename}'.",
                        evidence={"filename": z.filename},
                        module="fast_scan.docx.ole",
                    )
                )

            # External Relationships
            if z.filename.endswith(".rels"):
                try:
                    with zf.open(z) as f:
                        rel_content = f.read(512 * 1024)  # Read up to 512KB
                        if b'TargetMode="External"' in rel_content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                    severity=Severity.MEDIUM,
                                    title="DOCX External Relationship Found",
                                    explain=(
                                        "Found 'TargetMode=\"External\"' "
                                        f"in {z.filename}, "
                                        "indicating external content fetch."
                                    ),
                                    evidence={"filename": z.filename},
                                    module="fast_scan.docx.rels",
                                )
                            )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # Keyword Search in document.xml
            if z.filename == "word/document.xml":
                try:
                    # Read max 1MB of document.xml for speed
                    with zf.open(z) as f:
                        content = f.read(1024 * 1024)
                        content_lower = content.lower()
                        for kw in PROMPT_INJECTION_KEYWORDS:
                            if kw in content_lower:
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T4_PROMPT_INJECTION,
                                        severity=Severity.MEDIUM,
                                        title="Potential Injection Keyword (Fast Scan)",
                                        explain=(
                                            f"Found keyword '{kw.decode('ascii')}' "
                                            "in document.xml."
                                        ),
                                        evidence={"keyword": kw.decode("ascii")},
                                        module="fast_scan.docx.keywords",
                                    )
                                )

                        # Check stealth chars
                        for char_bytes, name in STEALTH_CHARS:
                            if char_bytes in content:
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T3_OBFUSCATION,
                                        severity=Severity.HIGH,
                                        title=f"Suspicious Hidden Character ({name})",
                                        explain=(
                                            f"Found {name} in XML, "
                                            "possible stealth injection."
                                        ),
                                        evidence={"char": name},
                                        module="fast_scan.docx.stealth",
                                    )
                                )
                                # Also flag as potential T4
                                # since this is a common injection vector
                                findings.append(
                                    Finding(
                                        threat_id=ThreatID.T4_PROMPT_INJECTION,
                                        severity=Severity.MEDIUM,
                                        title=(
                                            f"Potential Obfuscated "
                                            f"Injection ({name})"
                                        ),
                                        explain=(
                                            f"Found {name}, commonly used "
                                            "to hide prompt injections."
                                        ),
                                        evidence={"char": name},
                                        module="fast_scan.docx.stealth",
                                    )
                                )

                except Exception as e:
                    logger.debug("Error reading document.xml: %s", e)

        if suspicious_parts >= 2 or (
            overall_ratio > config.limits.max_docx_overall_expansion_ratio
            and total_mb > 10
        ):
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Suspicious Compression Ratio",
                    explain=(
                        "High compression ratio detected, characteristic of Zip "
                        "Bombs or generated obfuscation."
                    ),
                    evidence={
                        "overall_ratio": round(overall_ratio, 2),
                        "suspicious_parts": suspicious_parts,
                    },
                    module="fast_scan.docx.structure",
                )
            )

    return findings
