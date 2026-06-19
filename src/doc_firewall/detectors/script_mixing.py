"""W2 (0.5.0) — T4/T3: Language-agnostic script-mixing detection.

The most powerful *non-English* injection signal that needs no per-language
NLP: a document has a dominant writing system (an English résumé → Latin);
when a **hidden** text run or a **metadata** field carries a substantial run
in a *different* script (CJK, Cyrillic, Arabic, Hebrew, Devanagari, …), that
is a strong indicator of a concealed instruction — regardless of what it
says.

Why this does not false-positive on legitimately multilingual documents:
the detector inspects only **hidden** content (invisible text the analyzers
surfaced into ``doc.docx["hidden_text"]`` / ``doc.metadata["hidden_text"]``)
and **metadata** values — never the visible body. A bilingual contract or a
Chinese résumé whose second script is *visible* is not flagged. A short
foreign run (an author's name, a unit, one loanword) is below the length
threshold and ignored.

MITRE ATT&CK: T1027 (obfuscation). Threat code: T4 (the intent is prompt
injection) with a T3 obfuscation subtype on the hidden-text path.
"""
from __future__ import annotations

from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID, VerdictClass
from ..report import Finding
from ..utils.scripts import dominant_script, foreign_script_runs
from .base import Detector
from .metadata_injection import _collect_metadata_strings

_MITRE = "T1027"

# A foreign run must reach this many letters to count — keeps author names /
# single loanwords / unit symbols from firing.
_MIN_HIDDEN_CHARS = 8       # hidden text: lower bar (hidden + foreign is strong)
_MIN_METADATA_CHARS = 12    # metadata: higher bar (names live here)

# Human-readable script labels for explanations.
_SCRIPT_LABEL = {
    "LATIN": "Latin", "CYRILLIC": "Cyrillic", "GREEK": "Greek",
    "ARABIC": "Arabic", "HEBREW": "Hebrew", "CJK": "CJK (Chinese/Japanese/Korean)",
    "DEVANAGARI": "Devanagari", "BENGALI": "Bengali", "GURMUKHI": "Gurmukhi",
    "GUJARATI": "Gujarati", "TAMIL": "Tamil", "TELUGU": "Telugu",
    "THAI": "Thai", "LAO": "Lao", "ARMENIAN": "Armenian",
    "GEORGIAN": "Georgian", "ETHIOPIC": "Ethiopic",
}


def _label(group: str) -> str:
    return _SCRIPT_LABEL.get(group, group.title())


# Metadata keys that hold hidden text or comment bodies — handled by the
# hidden-text path, so the metadata-value path skips them to avoid
# double-flagging the same run.
_HIDDEN_KEYS = ("hidden_text", "_fast_hidden_text", "_pdf_object_text", "comments")


def _gather_hidden(doc: ParsedDocument) -> List[str]:
    out: List[str] = []
    # `_fast_hidden_text` is the scanner's bridge of fast-scan hidden text;
    # `hidden_text` is set directly by the xlsx/pptx/odf parsers;
    # `_pdf_object_text` is text from non-rendered PDF surfaces (W4.1).
    for container in (doc.docx, doc.pptx, doc.xlsx, doc.metadata):
        if not container:
            continue
        for key in ("hidden_text", "_fast_hidden_text", "_pdf_object_text"):
            val = container.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend(v for v in val if isinstance(v, str))
    return out


class ScriptMixingDetector(Detector):
    name = "script_mixing"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_script_mixing", True):
            return []

        # Establish the document's dominant script from the VISIBLE body.
        body = doc.text or ""
        dom, total = dominant_script(body)
        # Need a reliable baseline — too little visible text means we can't
        # say what's "foreign". (The keyword + ML layers still cover this.)
        if dom is None or total < 20:
            return []

        findings: List[Finding] = []

        # 1. Hidden text in a non-dominant script — strongest signal.
        for content in _gather_hidden(doc):
            for group, count, sample in foreign_script_runs(
                content, dom, _MIN_HIDDEN_CHARS
            ):
                findings.append(Finding(
                    threat_id=ThreatID.T4_PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    title=f"Hidden text in foreign script ({_label(group)})",
                    explain=(
                        f"This document is written predominantly in {_label(dom)}, "
                        f"but conceals {count} characters of hidden {_label(group)} "
                        "text. Hiding a run in a different writing system is a "
                        "common way to smuggle instructions past a human reviewer "
                        "into an LLM/RAG pipeline — independent of language."
                    ),
                    evidence={
                        "subtype": "hidden_foreign_script",
                        "dominant_script": dom,
                        "foreign_script": group,
                        "foreign_char_count": count,
                        "malicious_text": sample[:250],
                    },
                    module=self.name,
                    confidence=0.85,
                    mitre_technique=_MITRE,
                    attack_objective=(
                        "Conceal a non-English instruction from human review "
                        "while leaving it readable to a downstream LLM"
                    ),
                ))
                break  # one finding per hidden run is enough
            if findings:
                break  # one hidden-text script-mixing finding per document

        # 2. Metadata values in a non-dominant script (excluding the keys the
        # hidden-text path already covered).
        meta_for_values = {
            k: v for k, v in (doc.metadata or {}).items() if k not in _HIDDEN_KEYS
        }
        for value in _collect_metadata_strings(meta_for_values):
            runs = foreign_script_runs(value, dom, _MIN_METADATA_CHARS)
            if not runs:
                continue
            group, count, sample = runs[0]
            findings.append(Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                title=f"Metadata text in foreign script ({_label(group)})",
                explain=(
                    f"A metadata field contains a substantial {_label(group)} run "
                    f"({count} characters) in an otherwise {_label(dom)} document. "
                    "Metadata is a common surface for hiding instructions that a "
                    "viewer won't show but an LLM/RAG parser will read."
                ),
                evidence={
                    "subtype": "metadata_foreign_script",
                    "dominant_script": dom,
                    "foreign_script": group,
                    "foreign_char_count": count,
                    "malicious_text": sample[:250],
                },
                module=self.name,
                confidence=0.6,
                mitre_technique=_MITRE,
                attack_objective=(
                    "Hide a non-English instruction in document metadata"
                ),
                # MEDIUM/REVIEW: contributes to FLAG, not BLOCK on its own —
                # metadata legitimately carries non-Latin author/title text.
                verdict_class=VerdictClass.REVIEW,
            ))
            break  # one metadata script-mixing finding per document

        return findings
