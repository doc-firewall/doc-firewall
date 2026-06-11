from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from .enums import Verdict, Severity, ThreatID, VerdictClass


@dataclass
class Finding:
    threat_id: ThreatID
    severity: Severity
    title: str
    explain: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    location: Optional[str] = None
    module: Optional[str] = None
    # Default is 0.5 (neutral/unknown) rather than 1.0 to prevent unset
    # findings from contributing full weight to the risk score (R1).
    confidence: float = 0.5
    weight: float = 0.0  # Effective weight calculated by Risk Model

    # B.19 — Structured threat intelligence fields (optional; populated where known)
    cve: Optional[str] = None               # e.g. "CVE-2017-11882"
    mitre_technique: Optional[str] = None   # e.g. "T1059.007"
    attack_objective: Optional[str] = None  # Plain-English attacker goal

    # Verdict-driving class — see enums.VerdictClass. Default REVIEW is
    # safe: an unaudited finding contributes to the score and can FLAG
    # but cannot BLOCK. Definitive detectors (YARA, EICAR, javascript:,
    # JBIG2 exploit pattern, etc.) explicitly set this to BLOCK; purely
    # informational findings set it to INFO.
    verdict_class: VerdictClass = VerdictClass.REVIEW

    # Under-the-hood technical context — populated by the
    # detectors.explanations.enrich_findings() post-process for findings
    # whose `explain` is rewritten to plain English. Lets SIEMs / forensic
    # analysts see the original technical detail without losing the
    # human-readable summary in `explain`. None for findings the enricher
    # didn't recognise (their `explain` stays technical, no rewrite).
    technical_detail: Optional[str] = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return (
            self.threat_id == other.threat_id
            and self.severity == other.severity
            and self.title == other.title
            and self.explain == other.explain
            and self.location == other.location
            and self.module == other.module
            and round(self.confidence, 6) == round(other.confidence, 6)
        )

    def __hash__(self) -> int:
        return hash((self.threat_id, self.severity, self.title, self.module))


@dataclass
class ScanReport:
    file_path: str
    file_type: str
    sha256: str
    size_bytes: int

    verdict: Verdict = Verdict.ALLOW
    risk_score: float = 0.0
    findings: List[Finding] = field(default_factory=list)

    timings_ms: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    skipped_detectors: List[str] = field(default_factory=list)

    # Optional field to return the parsed content (e.g., safe markdown)
    # This allows developers to use DocFirewall as a single entry point for intake
    content: Optional[Dict[str, Any]] = None

    # H.11 (0.4.8): coverage transparency — which optional detection
    # capabilities (YARA/AV malware sigs, semantic/OCR/BERT injection) were
    # active for this scan. Lets a caller see when a verdict was produced in
    # reduced-coverage mode. Populated by Scanner; None for hand-built reports.
    coverage: Optional[Dict[str, Any]] = None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScanReport):
            return NotImplemented
        return (
            self.file_path == other.file_path
            and self.sha256 == other.sha256
            and self.verdict == other.verdict
            and round(self.risk_score, 6) == round(other.risk_score, 6)
            and self.findings == other.findings
        )

    def __hash__(self) -> int:
        return hash((self.sha256, self.verdict))

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["findings"] = [
            {**asdict(f), "threat_id": f.threat_id.value, "severity": f.severity.value}
            for f in self.findings
        ]
        return d
