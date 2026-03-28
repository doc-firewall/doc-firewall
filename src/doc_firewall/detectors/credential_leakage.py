import math
import re
import logging
from collections import Counter
from typing import List

from .base import Detector
from ..report import Finding
from ..config import ScanConfig
from ..analyzers.base import ParsedDocument
from ..enums import ThreatID, Severity

logger = logging.getLogger(__name__)

class CredentialLeakageDetector(Detector):
    name = "credential_leakage"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        findings = []
        if not config.enable_credential_entropy:
            return findings

        full_text = getattr(doc, 'text', '') or ""
        if not full_text:
            return findings

        # Find long spaceless strings (potential keys/secrets)
        # Regex looks for alphanumeric blocks with typical secret characters like _ - =
        matches = re.finditer(r'[a-zA-Z0-9_\-\=]{40,}', full_text)
        
        for match in matches:
            candidate = match.group(0)
            entropy = self._shannon_entropy(candidate)
            
            # Standard english text runs ~3.5 to 5.0
            # High entropy (> 4.8 on a tight alphabet, or > 5.5 overall) strongly indicates a key
            if entropy > 5.5:
                findings.append(Finding(
                    threat_id=ThreatID.T8_METADATA_INJECTION, # Can map to Data Leakage/Exfiltration
                    severity=Severity.HIGH,
                    confidence=0.90,
                    title="High Entropy String Block",
                    explain=f"High Shannon entropy ({entropy:.2f}) detected in string block; potential credential leakage or hardcoded key."
                ))
                # Only flag once per document to avoid alert fatigue
                break

        return findings

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        p, lns = Counter(s), float(len(s))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())