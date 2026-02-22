from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity


class MetadataInjectionDetector(Detector):
    name = "metadata_injection"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_metadata_checks:
            return []

        findings = []

        # Gather all metadata-like content
        targets: List[str] = []
        if doc.metadata:
            for k, v in doc.metadata.items():
                if k in [
                    "title",
                    "subject",
                    "creator",
                    "description",
                    "lastModifiedBy",
                ] and isinstance(v, str):
                    targets.append(v)
                elif k == "comments" and isinstance(v, list):
                    targets.extend(v)
                elif isinstance(v, str):
                    # fallback for other fields
                    targets.append(v)

        # Also check docx specific fields if not already in metadata
        if doc.docx:
            if "comments" in doc.docx:
                targets.extend(doc.docx["comments"])

        # T8 Checks
        for content in targets:
            if not content:
                continue

            # 1. Length check (Buffer overflow / DoS vector via metadata)
            if len(content) > 5000:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.HIGH,
                        title="Excessive Metadata/Comment Length",
                        explain=(
                            "Found metadata or comment field exceeding 5000 characters."
                        ),
                        evidence={"length": len(content), "snippet": content[:50]},
                        module=self.name,
                        confidence=0.8,
                    )
                )

            # 2. Syntax Injection (HTML/JS)
            if re.search(
                r"<script|javascript:|vbscript:|onload=|onerror=",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Script Injection in Metadata",
                        explain=(
                            "Detailed script tags or event handlers found "
                            "in metadata/comments."
                        ),
                        evidence={"snippet": content[:100]},
                        module=self.name,
                        confidence=1.0,
                    )
                )

            # 3. Prompt Injection in Metadata (T8/T4 crossover)
            # "Ignore previous instructions", "System Prompt"
            pi_patterns = [
                r"ignore\s+(?:all\s+)?previous\s+instructions",
                r"system\s+prompt",
                r"you\s+are\s+a\s+helper",
                r"do\s+not\s+reveal",
                r"rank\s+candidate\s+top",
                r"override\s+instruction",
                r"new\s+role\s+is",
                r"documents\s+above\s+are",
                r"interpret\s+this\s+document\s+as",
            ]
            for pat in pi_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T8_METADATA_INJECTION,
                            severity=Severity.HIGH,
                            title="Prompt Injection in Metadata",
                            explain=(
                                "Potentially malicious instructions found in "
                                "document metadata."
                            ),
                            evidence={"snippet": content[:100], "pattern": pat},
                            module=self.name,
                            confidence=0.9,
                        )
                    )
                    break

        return findings
