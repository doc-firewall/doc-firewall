from __future__ import annotations
from typing import List
from collections import Counter
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity


class RankingManipulationDetector(Detector):
    name = "ranking_manipulation"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_ranking_abuse:
            return []
        text = (doc.text or "").lower()
        tokens = [t for t in text.split() if t.isalpha() and len(t) > 2]
        if len(tokens) < 200:
            return []
        counts = Counter(tokens)
        most_common, freq = counts.most_common(1)[0]
        ratio = freq / max(1, len(tokens))
        if ratio > 0.08:
            return [
                Finding(
                    threat_id=ThreatID.T5_RANKING_MANIPULATION,
                    severity=Severity.MEDIUM,
                    title="Possible keyword stuffing",
                    explain=(
                        "Unusually high repetition of a single token may indicate "
                        "automated ranking manipulation."
                    ),
                    evidence={
                        "token": most_common,
                        "freq": freq,
                        "token_count": len(tokens),
                        "ratio": ratio,
                    },
                    module="detectors.ranking_manipulation",
                )
            ]
        return []
