from __future__ import annotations
import re
import math
from typing import List
from ...enums import ThreatID, Severity
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()

# Tokens to watch for in raw stream
SUSPICIOUS_TOKENS = [
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/Filespec",
    b"/URI",
    b"/Encrypt",
    b"/AcroForm",
]

# Simple Soft-Signal keywords for Prompt Injection (triage only)
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


def _byte_entropy(data: bytes) -> float:
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


def fast_scan_pdf(file_path: str, config: ScanConfig) -> List[Finding]:
    findings = []

    limit_bytes = config.limits.fast_pdf_token_scan_mb * 1024 * 1024

    with open(file_path, "rb") as f:
        data = f.read(limit_bytes)

    # 1. Token Scan (Active Content)
    # Valid PDF delimiters to ensure token is a real key
    delims_pattern = b"[\x00\t\n\f\r ()<>\\[\\]{}/%]"

    for token in SUSPICIOUS_TOKENS:
        if token in data:
            # Verify it's a valid key (must be followed by a delimiter)
            if not re.search(re.escape(token) + delims_pattern, data):
                continue

            sev = Severity.MEDIUM
            if token in [b"/OpenAction", b"/Launch", b"/Encrypt"]:
                sev = Severity.HIGH

            findings.append(
                Finding(
                    threat_id=(
                        ThreatID.T2_ACTIVE_CONTENT
                        if token != b"/Encrypt"
                        else ThreatID.T3_OBFUSCATION
                    ),
                    severity=sev,
                    title="Suspicious PDF Token found: {}".format(
                        token.decode("ascii", errors="ignore")
                    ),
                    explain="Found suspicious token '{}' in raw file stream.".format(
                        token.decode("ascii", errors="ignore")
                    ),
                    evidence={"token": token.decode("ascii", errors="ignore")},
                    module="fast_scan.pdf.tokens",
                )
            )

    # 2. Prompt Injection Soft Signals
    # DISABLED: We disable early T4 detection in Fast Scan because it cannot
    # distinguish between Body text and Metadata (T8). The Deep Parser + T4
    # Detector is robust enough to catch these without generating FPs on T8 files.

    # data_lower = data.lower()
    # for kw in PROMPT_INJECTION_KEYWORDS:
    #     if kw in data_lower:
    #         findings.append(Finding(
    #             threat_id=ThreatID.T4_PROMPT_INJECTION,
    #             severity=Severity.MEDIUM, # Trigger deep scan
    #             title="Potential Injection Keyword (Fast Scan)",
    #             explain=f"Found keyword '{kw.decode('ascii')}' in raw stream.",
    #             evidence={"keyword": kw.decode('ascii')},
    #             module="fast_scan.pdf.keywords"
    #         ))

    # 2b. Stealth Characters (Obfuscation)
    for char_bytes, name in STEALTH_CHARS:
        if char_bytes in data:
            findings.append(
                Finding(
                    threat_id=ThreatID.T3_OBFUSCATION,
                    # High enough to trigger deep scan (0.30 > 0.20)
                    severity=Severity.HIGH,
                    title=f"Suspicious Hidden Character ({name})",
                    explain=(
                        f"Found {name} in raw stream, often used for "
                        "stealth injections."
                    ),
                    evidence={"char": name},
                    module="fast_scan.pdf.stealth",
                )
            )
            # DISABLED: Do not cross-pollinate T4 verdicts here. T3 is sufficient.
            # Also flag as potential T4
            # findings.append(Finding(
            #     threat_id=ThreatID.T4_PROMPT_INJECTION,
            #     # ...
            # ))

    # 3. V2 Multi-Signal Obfuscation Logic
    signals = []

    # Signal A: Object Density
    obj_count = data.count(b" obj")
    if obj_count >= 1500:  # Lowered threshold for signal
        signals.append("high_obj_count")

    # 4. DoS Checks (Added for T6) - Production Generalization
    # Instead of a hard threshold (e.g. > 3000), we use Density (Objects/Page)
    # to distinguish between "Valid Large Doc" (many pages) and "PDF Bomb"
    # (few pages, massive objects).

    # Attempt to extract page count
    page_match = re.search(rb"/Type\s*/Pages\s*/Count\s+(\d+)", data)
    if not page_match:
        page_match = re.search(rb"/Count\s+(\d+)", data)

    page_count = 1  # Default to 1 to be conservative (assume high density if unknown)
    if page_match:
        try:
            page_count = int(page_match.group(1))
            if page_count < 1:
                page_count = 1
        except Exception:
            page_count = 1

    # Heuristics:
    # 1. Absolute Sanity Limit: 25,000 objects (Very large for any PDF header scan)
    # 2. Density Threshold: > 750 objects per page (Synthetic attack is ~4000)
    #    Real world equivalent: 50 page doc with 3500 objects = 70 obj/page (SAFE)

    is_dos_suspect = False

    if obj_count > 25000:
        is_dos_suspect = True
    elif obj_count > 3000 and (obj_count / page_count) > 750:
        is_dos_suspect = True

    if is_dos_suspect:
        findings.append(
            Finding(
                threat_id=ThreatID.T6_DOS,
                severity=Severity.HIGH,
                title="Suspicious Object Density (DoS)",
                explain=(
                    f"High object density detected: {obj_count} objects across "
                    f"{page_count} pages ({int(obj_count / page_count)} obj/page)."
                ),
                evidence={
                    "obj_count": obj_count,
                    "page_count": page_count,
                    "density": obj_count / page_count,
                },
                module="fast_scan.pdf.dos",
            )
        )

    # Clean up old density check logic to avoid duplication
    if page_match and not is_dos_suspect:
        try:
            if page_count > 2000:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="High Page Count (DoS)",
                        explain=f"Detected page count {page_count}, potential DoS.",
                        evidence={"page_count": page_count},
                        module="fast_scan.pdf.dos",
                    )
                )
        except Exception as e:
            logger.debug("Error checking page count: %s", e)

    # Signal B: Filter Count
    filter_count = data.count(b"/Filter")
    if filter_count >= 30:
        signals.append("high_filter_count")

    # Signal C: Entropy
    ent = _byte_entropy(data)
    if ent >= 7.95 and len(data) >= 1024 * 1024:
        signals.append("high_entropy")

    # Decision
    if len(signals) >= 2:
        findings.append(
            Finding(
                threat_id=ThreatID.T3_OBFUSCATION,
                severity=Severity.HIGH,
                title="PDF Obfuscation Detected (Multi-Signal)",
                explain=(
                    f"Detected multiple obfuscation indicators: {', '.join(signals)}."
                ),
                evidence={
                    "signals": signals,
                    "obj_count": obj_count,
                    "filter_count": filter_count,
                    "entropy": ent,
                },
                module="fast_scan.pdf.obfuscation",
            )
        )

    return findings
