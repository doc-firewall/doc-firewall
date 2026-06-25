from __future__ import annotations

from collections import Counter
from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID
from ..report import Finding
from .ats_manipulation import _STOP_WORDS, _strip_extraction_noise
from .base import Detector


class RankingManipulationDetector(Detector):
    name = "ranking_manipulation"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_ranking_abuse:
            return []
        # Strip Docling extraction artifacts (`<!-- image -->`, `Figure 5`,
        # etc.) before frequency analysis so the keyword stuffing check
        # operates on real content.
        text = _strip_extraction_noise(doc.text or "").lower()
        tokens = [
            t for t in text.split()
            if t.isalpha() and len(t) > 2 and t not in _STOP_WORDS
        ]
        if len(tokens) < 50:
            return []
        counts = Counter(tokens)
        most_common, freq = counts.most_common(1)[0]
        ratio = freq / max(1, len(tokens))
        # Require both a ratio threshold and a minimum absolute count. The
        # threshold is set at 15%, not 8%: real topical/technical documents
        # (a privacy policy repeating "data", a contract repeating "agreement",
        # an insurance form repeating "policy") legitimately peak around
        # 8-12% for their dominant term, so an 8% bar false-fired across the
        # benign corpus. Mechanical ranking stuffing concentrates a token far
        # higher (20%+); 15% separates the two with margin to spare.
        if ratio > 0.15 and freq >= 12:
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
                        "malicious_text": most_common[:250],
                    },
                    module="detectors.ranking_manipulation",
                )
            ]
        return []
