"""W2 (0.5.0) — T4: bundled injection classifier (default-on, no extras).

The always-on regex/keyword layers catch *known* phrasings; this small
logistic-regression model (vendored in the wheel, numpy-only) generalises to
**paraphrased** injections the patterns miss — closing the biggest
default-install evasion gap. Multilingual by construction (the hashing
features are Unicode-aware).

Conservative by design: REVIEW-class (contributes to FLAG, never BLOCK on
its own) and calibrated for zero false positives on the benign corpus. If
the vendored model is absent/unloadable it silently disables (the other
layers still run).

NOTE: the shipped model is trained on synthetic + seed-derived data; retrain
on a real-world corpus (plan W1) before relying on it as a primary control.
"""
from __future__ import annotations

from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID, VerdictClass
from ..ml.injection_model import load_model
from ..report import Finding
from .base import Detector

_MITRE = "T1059"
# Scan the document in overlapping windows so a short injection inside a long
# document isn't diluted by the surrounding benign text.
_WINDOW = 400
_STRIDE = 200
_MAX_WINDOWS = 60


def _windows(text: str) -> List[str]:
    text = text.strip()
    if len(text) <= _WINDOW:
        return [text] if text else []
    out = []
    for start in range(0, len(text), _STRIDE):
        out.append(text[start:start + _WINDOW])
        if len(out) >= _MAX_WINDOWS:
            break
    return out


# A prompt injection is natural-language text. Raw byte extraction from a PDF
# (when the high-quality parser is unavailable) yields undecoded FlateDecode /
# inline-image streams — high-entropy binary that the classifier, trained only
# on prose, scores as injection. Natural language of ANY script carries almost
# no C0/C1 control characters; a compressed stream is dense with them. Windows
# above this control-character density are skipped — they are not text.
_MAX_CONTROL_RATIO = 0.02


def _control_ratio(s: str) -> float:
    if not s:
        return 0.0
    ctrl = sum(
        1 for c in s
        if (ord(c) < 0x20 and c not in "\t\n\r") or 0x7F <= ord(c) <= 0x9F
    )
    return ctrl / len(s)


class InjectionClassifierDetector(Detector):
    name = "injection_classifier"

    def __init__(self) -> None:
        self._model = None
        self._tried = False

    def _get_model(self):
        if not self._tried:
            self._model = load_model()
            self._tried = True
        return self._model

    def prepare(self, config: ScanConfig) -> None:
        if getattr(config, "enable_injection_classifier", True):
            self._get_model()

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_injection_classifier", True):
            return []
        model = self._get_model()
        if model is None:
            return []

        text = doc.text or ""
        if not text.strip():
            return []

        best_p = 0.0
        best_win = ""
        for win in _windows(text):
            # Skip non-text windows (binary / compressed PDF streams surfaced by
            # the raw-bytes fallback parser) — the model only reasons about prose.
            if _control_ratio(win) > _MAX_CONTROL_RATIO:
                continue
            p = model.score(win)
            if p > best_p:
                best_p, best_win = p, win

        if best_p < model.threshold:
            return []

        # Severity scales with confidence; capped at HIGH (REVIEW-class means
        # it can FLAG but never BLOCK on its own).
        sev = Severity.HIGH if best_p >= 0.85 else Severity.MEDIUM
        return [Finding(
            threat_id=ThreatID.T4_PROMPT_INJECTION,
            severity=sev,
            title="Prompt injection (ML classifier)",
            explain=(
                "A machine-learning classifier flagged this text as a likely "
                "prompt injection. Unlike the keyword layers it generalises to "
                "novel / paraphrased phrasings and is multilingual."
            ),
            evidence={
                "subtype": "ml_classifier",
                "probability": round(best_p, 3),
                "threshold": round(model.threshold, 3),
                "malicious_text": best_win.strip()[:250],
            },
            module=self.name,
            confidence=round(min(0.95, best_p), 3),
            mitre_technique=_MITRE,
            attack_objective="Manipulate an LLM/RAG pipeline via injected instructions",
            verdict_class=VerdictClass.REVIEW,
        )]
