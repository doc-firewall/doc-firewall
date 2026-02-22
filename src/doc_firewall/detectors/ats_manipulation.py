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

            # Check for repeated sequences (e.g. "Java Java Java Java")
            # This remains relevant for ATS as "white-text" blocks often look
            # like this.
            repeated_seq = re.search(r"(\b\w+\s+)\1{10,}", text)
            if repeated_seq:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Repeated Keywords Sequence",
                        explain=(
                            "Detected a sequence of identical words repeated 10+ times."
                        ),
                        evidence={"snippet": repeated_seq.group(0)[:50]},
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

        return findings
