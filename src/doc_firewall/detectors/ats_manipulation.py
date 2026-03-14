from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity


class ATSManipulationDetector(Detector):
    name = "ats_manipulation"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_ats_manipulation_checks:
            return []

        findings = []
        text = doc.text or ""

        # 1. Keyword Stuffing
        # Check for repeated words in close proximity or high frequency
        if text:
            # Simple frequency check moved to T5 (Ranking Manipulation) to
            # avoid overlapping FPs.
            # ATS manipulation mainly focuses on *hidden* stuffing or
            # mechanical sequence repetition.

            # words = [w.lower() for w in re.findall(r'\b\w{4,}\b', text)]
            # count = Counter(words)
            # ... (removed simple frequency check)

            # Check for repeated sequences (e.g. "Java Java Java Java" or "Best Candidate Best Candidate")
            # We match 1 to 4 words repeated at least 10 times.
            repeated_seq = re.search(r"(\b(?:\w+\s+){1,4})\1{10,}", text, flags=re.IGNORECASE)
            if repeated_seq:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Repeated Keywords Sequence",
                        explain="Detected a sequence of identical words repeated 10+ times.",
                        evidence={"snippet": repeated_seq.group(0)[:50]},
                        module=self.name,
                        confidence=0.9,
                    )
                )

            # Simple frequency check (also cover T9 since T5 overlap caused FNs)
            tokens = [t for t in text.lower().split() if t.isalpha() and len(t) > 2]
            if len(tokens) >= 50:
                from collections import Counter

                top_tokens = [k for k, v in Counter(tokens).most_common(3)]
                most_common, freq = Counter(tokens).most_common(1)[0]
                if freq / len(tokens) > 0.08:
                    is_ats = False
                    if most_common in set(config.ats_keywords):
                        is_ats = True
                    elif most_common == "top" and "candidate" in top_tokens:
                        is_ats = True

                    if is_ats:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T9_ATS_MANIPULATION,
                                severity=Severity.HIGH,
                                title="Keyword stuffing (ATS Manipulation)",
                                explain="Unusually high repetition of a single token.",
                                evidence={
                                    "token": most_common,
                                    "ratio": freq / len(tokens),
                                },
                                module=self.name,
                                confidence=0.9,
                            )
                        )

        # 2. Hidden Text / Font Size 0 (T9)
        if doc.metadata and "hidden_text" in doc.metadata:
            ht = doc.metadata["hidden_text"]
            if ht:
                # If list, join.
                if isinstance(ht, list):
                    ht = " ".join(ht)

                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Hidden Text Detected",
                        explain=(
                            "Found text hidden via 'vanish' property or "
                            "white-on-white/size-0 formatting."
                        ),
                        evidence={"snippet": ht[:100]},
                        module=self.name,
                        confidence=0.95,
                    )
                )

        # Check vanilla vanish attribute if not parsed into hidden_text but flagged
        if doc.metadata and doc.metadata.get("has_hidden_tags"):
            findings.append(
                Finding(
                    threat_id=ThreatID.T9_ATS_MANIPULATION,
                    severity=Severity.MEDIUM,
                    title="Hidden Text Tags Detected",
                    explain="Found XML tags indicating hidden text (<w:vanish/>).",
                    evidence={"tag": "w:vanish"},
                    module=self.name,
                    confidence=0.9,
                )
            )
        # If the analyzer populated hidden_text (e.g. from XML)
        if doc.docx and "hidden_text" in doc.docx:
            hidden = doc.docx["hidden_text"]
            if hidden:
                # If list or string
                content_len = len(str(hidden))
                if content_len > 0:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T9_ATS_MANIPULATION,
                            severity=Severity.MEDIUM,
                            title="Hidden Text Detected",
                            explain=(
                                "Document contains text marked as hidden, often "
                                "used for ATS manipulation."
                            ),
                            evidence={"length": content_len},
                            module=self.name,
                            confidence=0.9,
                        )
                    )

        # 3. High Zero Width / Bidi characters (used for hiding ATS keywords)
        ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}
        if text:
            zw_count = sum(1 for ch in text if ch in ZERO_WIDTH)
            text_len = max(1, len(text))
            if (
                zw_count >= 50
                and (zw_count / text_len) > config.obfuscation_zw_threshold_ratio
            ):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Hidden ATS Text via Zero-Width Characters",
                        explain="High number of zero-width characters used to hide ATS text.",
                        evidence={"zw_count": zw_count},
                        module=self.name,
                        confidence=0.9,
                    )
                )

        return findings
