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
            ThreatID.T5_RANKING_MANIPULATION: 0.6,
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

        De-duplication (R3): when multiple findings reference the same
        malicious_text artifact, only the highest-confidence one per
        threat_id group is kept.  This prevents two weak signals on the
        same piece of text from multiplying into a BLOCK verdict.
        """
        # Group by (threat_id, malicious_text_fingerprint); keep max confidence.
        best: dict[tuple, Finding] = {}
        for f in findings:
            artifact = (f.evidence or {}).get("malicious_text", "")
            # Truncate fingerprint to 80 chars to handle minor snippet differences
            key = (f.threat_id, artifact[:80])
            existing = best.get(key)
            if existing is None or f.confidence > existing.confidence:
                best[key] = f

        deduplicated = list(best.values())

        prod = 1.0
        for f in deduplicated:
            w_threat = self.threat_weights.get(f.threat_id, 0.5)
            w_sev = self.severity_weights.get(f.severity, 0.5)
            confidence = f.confidence  # Finding.confidence defaults to 0.5 (R1)
            p_detection = w_threat * w_sev * confidence
            prod *= 1.0 - max(0.0, min(1.0, p_detection))

        return 1.0 - prod

    def get_verdict(self, risk_score: float) -> Verdict:
        if risk_score > self.config.thresholds.block:
            return Verdict.BLOCK
        if risk_score >= self.config.thresholds.flag:
            return Verdict.FLAG
        return Verdict.ALLOW
