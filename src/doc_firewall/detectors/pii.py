from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

# Basic patterns for common PII
# Note: These are heuristic and not exhaustive.
# Enterprise usage often requires library specific PII tools (like Presidio).
PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", "Email Address"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "US SSN"),
    (r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b", "Phone Number (US)"),
    (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|"
        r"(?:2131|1800|35\d{3})\d{11})\b",
        "Credit Card Number",
    ),
]


class PiiDetector(Detector):
    name = "pii"

    def __init__(self):
        self.regexes = [(re.compile(p), name) for p, name in PATTERNS]

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_pii_checks:
            return []

        text = doc.text or ""
        # Limiting PII check to first 100k chars for performance if needed,
        # but PII can be anywhere. Assume full text for now.

        matches = []
        for regex, label in self.regexes:
            # finditer to get counts without storing all matches if too many
            count = 0
            examples = []
            for m in regex.finditer(text):
                count += 1
                if count <= 3:  # Capture first 3 examples
                    examples.append(m.group(0))

            if count > 0:
                matches.append({"type": label, "count": count, "examples": examples})

        if not matches:
            return []

        # Severity depends on what was found. SSN/CC is HIGH.
        # Email/Phone is LOW/INFO (often expected in resumes).
        severity = Severity.INFO
        for m in matches:
            if m["type"] in ["US SSN", "Credit Card Number"]:
                severity = Severity.HIGH
                break
            if m["type"] in ["Email Address", "Phone Number"]:
                # If we have a resume scanner, finding an email is expected, so
                # maybe just INFO or LOW.
                # But if we find 100 emails, it might be a leak.
                if m["count"] > 10:
                    severity = Severity.MEDIUM

        # Mapping to a ThreatID. We might need a new T-ID for Privacy.
        # For now, let's map to a generic warning or T2_ACTIVE_CONTENT as placeholder

        return [
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,  # Placeholder: ideally T_PRIVACY
                severity=severity,
                title="Personally Identifiable Information (PII) Detected",
                explain="The document contains patterns resembling PII.",
                evidence={"matches": matches},
                module="detectors.pii",
            )
        ]
