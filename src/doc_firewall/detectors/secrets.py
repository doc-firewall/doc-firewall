from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

PATTERNS = [
    (r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{20}", "AWS Access Key"),
    (r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
    (r"xox[baprs]-([0-9a-zA-Z]{10,48})", "Slack Token"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
]


class SecretsDetector(Detector):
    name = "secrets"

    def __init__(self):
        self.regexes = [(re.compile(p), name) for p, name in PATTERNS]

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_secrets_checks:
            return []

        text = doc.text or ""
        matches = []
        for regex, label in self.regexes:
            found = regex.findall(text)
            if found:
                matches.append({"type": label, "count": len(found)})

        if not matches:
            return []

        return [
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                title="Secrets/Credentials Detected",
                explain=(
                    "The document contains patterns resembling credentials "
                    "or private keys."
                ),
                evidence={"matches": matches},
                module="detectors.secrets",
            )
        ]
