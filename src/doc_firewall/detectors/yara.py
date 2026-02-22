from __future__ import annotations
import os
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()

try:
    import yara
except ImportError:
    yara = None


class YaraDetector(Detector):
    name = "yara"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_yara:
            return []

        # Fallback simple malware check if YARA is not fully configured or
        # for standard test strings
        # EICAR test string
        eicar_signature = (
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )

        findings = []
        text = doc.text or ""

        # Check text
        if eicar_signature in text:
            findings.append(
                Finding(
                    threat_id=ThreatID.T1_MALWARE,
                    severity=Severity.CRITICAL,
                    title="Malware Signature Detected (EICAR)",
                    explain="Found EICAR test string in document text.",
                    evidence={"signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
                    module=self.name,
                )
            )
            return findings  # CRITICAL stops scan usually

        # Custom/User-defined YARA rules
        if config.enable_yara and config.yara_rules_path:
            if yara is None:
                # Log warning in production: 'yara-python' not installed
                return findings

            if not os.path.exists(config.yara_rules_path):
                # Log warning: Rules file not found
                return findings

            try:
                rules = yara.compile(filepath=config.yara_rules_path)

                # Scan logical text first (fast)
                text_matches = rules.match(data=text)
                for m in text_matches:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T1_MALWARE,
                            severity=Severity.CRITICAL,
                            title=f"YARA Rule Match (Text): {m.rule}",
                            explain=f"Document text matched YARA rule '{m.rule}'",
                            evidence={"rule": m.rule, "tags": m.tags, "meta": m.meta},
                            module=f"{self.name}.text",
                        )
                    )

                # Scan binary file if available (comprehensive)
                if doc.file_path and os.path.isfile(doc.file_path):
                    file_matches = rules.match(filepath=doc.file_path)
                    for m in file_matches:
                        # Deduplicate if same rule matched both
                        if not any(f.evidence.get("rule") == m.rule for f in findings):
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T1_MALWARE,
                                    severity=Severity.CRITICAL,
                                    title=f"YARA Rule Match (Binary): {m.rule}",
                                    explain=f"File binary matched YARA rule '{m.rule}'",
                                    evidence={
                                        "rule": m.rule,
                                        "tags": m.tags,
                                        "meta": m.meta,
                                    },
                                    module=f"{self.name}.binary",
                                )
                            )
            except Exception as e:
                # In production, we would log this error
                logger.debug("Error running YARA scan: %s", e)

        return findings
