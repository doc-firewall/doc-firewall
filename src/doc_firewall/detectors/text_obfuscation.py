from __future__ import annotations
from typing import List
import math
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}
BIDI_CONTROLS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


def _shannon_entropy(s: str) -> float:
    if len(s) < 20:
        return 0.0  # Ignore short strings
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


class TextObfuscationDetector(Detector):
    name = "text_obfuscation"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_obfuscation_checks:
            return []
        text = doc.text or ""
        if not text:
            # Check fast scan artifacts if available (e.g. if PDF had /Encrypt)
            # but usually this detector focuses on the extracted text.
            return []

        # V3 Multi-signal Logic
        findings = []
        signals = []

        # 0. Check for /Encrypt Exception (Immediate Trigger)
        if doc.pdf and doc.pdf.get("encrypted_token", False):
            findings.append(
                Finding(
                    threat_id=ThreatID.T3_OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Found /Encrypt Token",
                    explain="File contains /Encrypt token, indicating PDF encryption.",
                    evidence={"token": "/Encrypt"},
                    module=self.name,
                )
            )
            return findings

        # 1. Zero Width / Unicode Stealth
        zw_count = sum(1 for ch in text if ch in ZERO_WIDTH)
        if zw_count >= 25:
            signals.append("high_zero_width")

        # 2. Bidi
        bidi_count = sum(1 for ch in text if ch in BIDI_CONTROLS)
        if bidi_count >= 2:
            signals.append("high_bidi")

        # 3. High Entropy (Obfuscated/Encrypted blocks)
        # Scan chunks
        chunks = [text[i : i + 500] for i in range(0, len(text), 500)]
        high_ent_chunks = 0
        for chunk in chunks:
            if len(chunk) < 50:
                continue
            if _shannon_entropy(chunk) > 5.5:  # 5.5 is typical base64 cutoff
                high_ent_chunks += 1

        if high_ent_chunks >= 2 or (
            len(chunks) > 0 and high_ent_chunks / len(chunks) > 0.3
        ):
            signals.append("high_entropy")

        # 4. Compression Anomaly (Passed from fast scan usually, check metadata)
        if doc.metadata and doc.metadata.get("compression_ratio", 0) > 100:
            signals.append("compression_anomaly")

        # 5. Encoded Payload (Base64 patterns)
        # REMOVED: T7 (Embedded Payload) detector covers base64/hex specifically.
        # Including it here causes FPs on T7 files.
        # if re.search(r'[A-Za-z0-9+/]{1000,}={0,2}', text):
        #      signals.append("encoded_payload")

        # 6. Object Density (PDF specific)
        if doc.pdf:
            obj_count = doc.pdf.get("obj_count", 0)
            page_count = doc.pdf.get("page_count", 1) or 1
            if obj_count / page_count > 1000:  # Heuristic
                signals.append("high_object_density")

        # Decision: Trigger T3 only if 2+ signals
        if len(signals) >= 2:
            findings.append(
                Finding(
                    threat_id=ThreatID.T3_OBFUSCATION,
                    severity=Severity.HIGH,
                    title="Obfuscation Detected (Multi-Signal)",
                    explain=(
                        f"Detected multiple obfuscation signals: "
                        f"{', '.join(signals)}"
                    ),
                    evidence={"signals": signals, "count": len(signals)},
                    module=self.name,
                )
            )

        return findings
