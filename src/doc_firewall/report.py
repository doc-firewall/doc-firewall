from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from .enums import Verdict, Severity, ThreatID


@dataclass
class Finding:
    threat_id: ThreatID
    severity: Severity
    title: str
    explain: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    location: Optional[str] = None
    module: Optional[str] = None
    confidence: float = 1.0
    weight: float = 0.0  # Effective weight calculated by Risk Model


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
