from typing import Dict, List, Optional
from .enums import Severity, ThreatID, Verdict, VerdictClass
from .report import Finding
from .config import ScanConfig


class RiskModel:
    def __init__(self, config: ScanConfig) -> None:
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
            ThreatID.T10_INDIRECT_INJECTION: 0.8,
            ThreatID.T11_RAG_POISONING: 0.8,
            ThreatID.T12_SOCIAL_ENGINEERING: 0.75,
        }

        # Severity mappings
        self.severity_weights: Dict[Severity, float] = {
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.50,
            Severity.HIGH: 0.80,
            Severity.CRITICAL: 1.00,
        }

    def calculate_risk(
        self,
        findings: List[Finding],
        custom_threat_weights: Optional[Dict[str, float]] = None,
    ) -> float:
        """
        Probabilistic scoring: risk = 1 - Π(1 - weight * severity * confidence)

        De-duplication (R3): when multiple findings reference the same
        malicious_text artifact, only the highest-confidence one per
        threat_id group is kept.  This prevents two weak signals on the
        same piece of text from multiplying into a BLOCK verdict.
        """
        # INFO-class findings are recorded for audit but do not contribute
        # to the risk score — they're descriptive (e.g. "PDF has 2 update
        # layers") and matching them against a probabilistic threshold
        # produces noise, not signal. The verdict logic also ignores them.
        scoring_findings = [
            f for f in findings if f.verdict_class != VerdictClass.INFO
        ]

        # Group by (threat_id, malicious_text_fingerprint); keep max confidence.
        #
        # Key strategy: when the finding carries a non-empty malicious_text
        # artifact, deduplicate purely on (threat_id, artifact) — this collapses
        # the fast-scan T4 byte hit and the deep-scan T4 pattern match for the
        # same keyword into a single finding (the higher-confidence one wins).
        # When the artifact is empty, include title to prevent unrelated findings
        # — e.g. two distinct T6 timeout findings — from wrongly merging.
        best: dict[tuple, Finding] = {}
        for f in scoring_findings:
            artifact = (f.evidence or {}).get("malicious_text", "")
            if artifact:
                key: tuple = (f.threat_id, artifact[:80])
            else:
                key = (f.threat_id, f.title[:40], "")
            existing = best.get(key)
            if existing is None or f.confidence > existing.confidence:
                best[key] = f

        deduplicated = list(best.values())

        # Merge in policy-level overrides (keyed by ThreatID.value string)
        effective_weights = dict(self.threat_weights)
        if custom_threat_weights:
            for key, val in custom_threat_weights.items():
                try:
                    tid = ThreatID(key)
                    effective_weights[tid] = float(val)
                except ValueError:
                    pass  # Unknown key — ignore rather than crash

        prod = 1.0
        for f in deduplicated:
            w_threat = effective_weights.get(f.threat_id, 0.5)
            w_sev = self.severity_weights.get(f.severity, 0.5)
            confidence = f.confidence  # Finding.confidence defaults to 0.5 (R1)
            p_detection = w_threat * w_sev * confidence
            prod *= 1.0 - max(0.0, min(1.0, p_detection))

        return 1.0 - prod

    def get_verdict(
        self,
        risk_score: float,
        findings: Optional[List[Finding]] = None,
    ) -> Verdict:
        """Derive the scan verdict from finding classes (not from the score).

        New (post-0.4.4) semantics:

          - **BLOCK** iff any finding has ``verdict_class == BLOCK``. This
            class is reserved for definitive evidence — YARA signature
            matches, ``javascript:`` URIs, EICAR, ``/JavaScript`` +
            ``/OpenAction`` co-occurrence, JBIG2Decode exploit pattern,
            embedded PE/ELF in a non-archive, etc. No combination of weaker
            (REVIEW-class) findings can produce a BLOCK.
          - **FLAG** iff any finding has ``verdict_class == REVIEW`` (the
            default for new / unaudited findings). These are heuristic
            signals worth human attention but not by themselves proof of
            malice.
          - **ALLOW** otherwise (no findings, or only ``INFO``-class
            findings recorded for audit).

        ``risk_score`` is still computed and exposed for analytics, but no
        longer gates the verdict. ``thresholds.flag`` / ``thresholds.block``
        in the config are kept for backwards compatibility with downstream
        tools that label the numeric score band, but they no longer drive
        BLOCK / FLAG decisions.

        If ``findings`` is omitted, falls back to the legacy score-band
        behaviour so old callers don't break — but every internal
        Scanner code path passes findings.
        """
        if findings is not None:
            classes = {f.verdict_class for f in findings}
            if VerdictClass.BLOCK in classes:
                return Verdict.BLOCK
            if VerdictClass.REVIEW in classes:
                return Verdict.FLAG
            return Verdict.ALLOW

        # Legacy score-band fallback for external callers that haven't been
        # updated. Emits a deprecation warning the first time it fires.
        import warnings
        warnings.warn(
            "RiskModel.get_verdict(risk_score) without findings is deprecated; "
            "pass the findings list so verdict can be derived from finding classes.",
            DeprecationWarning,
            stacklevel=2,
        )
        if risk_score > self.config.thresholds.block:
            return Verdict.BLOCK
        if risk_score >= self.config.thresholds.flag:
            return Verdict.FLAG
        return Verdict.ALLOW
