from typing import List, Dict
from .enums import Severity, ThreatID, Verdict
from .report import Finding
from .config import ScanConfig


class RiskModel:
    def __init__(self, config: ScanConfig):
        self.config = config
        # Default Weights per ThreatID
        self.threat_weights: Dict[ThreatID, float] = {
            ThreatID.T1_MALWARE: 1.0,
            ThreatID.T2_ACTIVE_CONTENT: 0.9,
            ThreatID.T3_OBFUSCATION: 0.5,
            ThreatID.T4_PROMPT_INJECTION: 0.8,
            ThreatID.T5_RANKING_MANIPULATION: 0.4,
            ThreatID.T6_DOS: 0.9,
            ThreatID.T7_EMBEDDED_PAYLOAD: 0.7,
            ThreatID.T8_METADATA_INJECTION: 0.6,
            ThreatID.T9_ATS_MANIPULATION: 0.5,
        }

        # Severity mappings
        self.severity_weights: Dict[Severity, float] = {
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.50,
            Severity.HIGH: 0.80,
            Severity.CRITICAL: 1.00,
        }

    def calculate_risk(self, findings: List[Finding]) -> float:
        """
        Probabilistic scoring: risk = 1 - Π(1 - weight * severity * confidence)
        """
        prod = 1.0
        for f in findings:
            w_threat = self.threat_weights.get(f.threat_id, 0.5)
            w_sev = self.severity_weights.get(f.severity, 0.5)
            # Ensure confidence is 0.0-1.0. If missing, assume 1.0?
            # Finding usually has confidence. Let's assume it's exposed or default to
            # 1.0 if not.
            # Assuming Finding object has confidence attribute, if not we need to
            # update Finding.
            confidence = getattr(f, "confidence", 1.0)

            p_detection = w_threat * w_sev * confidence
            prod *= 1.0 - max(0.0, min(1.0, p_detection))  # Clamp probability

        return 1.0 - prod

    def get_verdict(self, risk_score: float) -> Verdict:
        if risk_score > self.config.thresholds.block:
            return Verdict.BLOCK
        if risk_score >= self.config.thresholds.flag:
            return Verdict.FLAG
        return Verdict.ALLOW
