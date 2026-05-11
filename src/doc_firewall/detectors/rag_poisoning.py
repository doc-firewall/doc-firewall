"""C.2 — T11: RAG / Knowledge-Base Poisoning detector.

Three sub-detectors (each independently gated):

  Sub-A  Authority assertion phrases — always active, pure regex. Fires when
         the document claims to supersede, override, or update the AI system's
         knowledge base or context. MEDIUM with 1-2 anchors; HIGH with 3+.

  Sub-B  Repetitive context flooding — gated by enable_semantic_nn. Fires
         when > 40 % of document sentences are near-duplicates, indicating
         the document was crafted to amplify a malicious phrase's retrieval
         frequency in the vector store.

  Sub-C  False authority citation — gated by enable_advanced_bert. Fires
         when a recognized authority body (NIST, ISO, FBI …) co-occurs with
         an imperative verb within 300 characters, a pattern used to lend
         false legitimacy to injected instructions.

MITRE ATT&CK: T1565.001 — Stored Data Manipulation.
"""
from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

# ── Sub-A: Authority assertion / context-override phrases ─────────────────────

_AUTHORITY_PATTERNS: list[re.Pattern[str]] = [
    # 1. Supersession of AI instructions / context
    re.compile(
        r'\bsupersedes?\s+(?:all\s+)?(?:previous|prior|existing|earlier)\s+'
        r'(?:instructions?|rules?|context|knowledge|guidelines?|directives?|'
        r'entries?|records?|prompts?|training|constraints?)',
        re.IGNORECASE,
    ),
    # 2. Override / replace knowledge-base entries
    re.compile(
        r'\b(?:overrides?|replaces?|voids?|invalidates?)\s+(?:all\s+)?'
        r'(?:previous|prior|existing)\s+'
        r'(?:entries?|records?|instructions?|context|knowledge|guidelines?|directives?)',
        re.IGNORECASE,
    ),
    # 3. Explicit SYSTEM OVERRIDE keyword
    re.compile(r'\bSYSTEM\s+OVERRIDE\b', re.IGNORECASE),
    # 4. Admin / system-authority impersonation
    re.compile(
        r'\b(?:I\s+am|speaking\s+as|writing\s+as)\s+(?:your\s+)?'
        r'(?:system\s+administrator|the\s+system|an?\s+administrator|the\s+owner)\b',
        re.IGNORECASE,
    ),
    # 5. "Treat this as the authoritative / primary source" framing
    re.compile(
        r'\btreat\s+(?:this|the\s+following|it)\s+as\s+(?:the\s+)?'
        r'(?:primary|authoritative|canonical|official|definitive)\b',
        re.IGNORECASE,
    ),
    # 6. Knowledge-base / vector-store update claims
    re.compile(
        r'\b(?:your\s+)?(?:knowledge\s+base|training\s+data|vector\s+store)\s+'
        r'(?:has\s+been\s+|have\s+been\s+)?updated\b',
        re.IGNORECASE,
    ),
    # 7. Role / instruction update claims
    re.compile(
        r'\byour\s+(?:role|instructions?|guidelines?)\s+'
        r'(?:has\s+been\s+|have\s+been\s+)?updated\b',
        re.IGNORECASE,
    ),
    # 8. Priority / precedence over other KB content
    re.compile(
        r'\bthis\s+(?:document|entry|record|chunk|content)\s+takes?\s+'
        r'(?:priority|precedence)\b',
        re.IGNORECASE,
    ),
    # 9. Persona / authorization update
    re.compile(
        r'\byou\s+are\s+now\s+(?:authorized|configured|instructed|designated|trained)\b',
        re.IGNORECASE,
    ),
    # 10. Explicit "new [system] context / instructions:" header
    re.compile(
        r'\bnew\s+(?:system\s+)?(?:context|instructions?|guidelines?)\s*:\s*\S',
        re.IGNORECASE,
    ),
]

_A_HIGH_THRESHOLD = 3  # ≥ 3 distinct anchors escalates to HIGH

# ── Sub-B: Repetitive context flooding ────────────────────────────────────────

_B_MIN_SENTENCES = 8
_B_DUPLICATE_RATIO_HIGH = 0.60
_B_DUPLICATE_RATIO_MEDIUM = 0.40
_SENTENCE_SPLIT_RE = re.compile(r'(?<=[.!?])\s+')


def _flooding_stats(text: str) -> tuple[float, int, int]:
    """Return (duplicate_ratio, total_sentences, unique_sentences)."""
    raw = _SENTENCE_SPLIT_RE.split(text.strip())
    sentences = [re.sub(r'\s+', ' ', s.strip().lower()) for s in raw if len(s.strip()) > 20]
    if len(sentences) < _B_MIN_SENTENCES:
        return 0.0, len(sentences), len(sentences)
    unique = len(set(sentences))
    total = len(sentences)
    return 1.0 - (unique / total), total, unique


# ── Sub-C: False authority citation ───────────────────────────────────────────

_AUTHORITY_BODIES_RE = re.compile(
    r'\b(?:per|according\s+to|as\s+stated\s+by|as\s+mandated\s+by|per\s+guidance\s+from)\s+'
    r'(?:NIST|ISO|IEC|FBI|DHS|NSA|CISA|DoD|MITRE|OWASP|OpenAI|Anthropic|'
    r'IEEE|W3C|RFC\s*\d{4}|the\s+(?:federal\s+)?government|'
    r'the\s+(?:IT|security)\s+team|management|legal|compliance|HR|your\s+employer)\b',
    re.IGNORECASE,
)

_IMPERATIVE_RE = re.compile(
    r'\b(?:must|shall|should|always|never|immediately|ensure|confirm|send|provide|'
    r'submit|click|download|install|enable|disable|allow|grant|approve|ignore|'
    r'disregard|override|bypass|execute|run|apply|follow|comply|reset|update)\b',
    re.IGNORECASE,
)

_C_WINDOW = 300
_MITRE = "T1565.001"
_OBJECTIVE = "Poison AI knowledge base by asserting document authority over retrieved context"


class RAGPoisoningDetector(Detector):
    """C.2 — T11: RAG / Knowledge-Base Poisoning detection."""

    name = "rag_poisoning"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_rag_poisoning", True):
            return []

        findings: List[Finding] = []
        text = doc.text or ""
        if not text:
            return findings

        # ── Sub-A ─────────────────────────────────────────────────────────────
        hits: list[str] = []
        for pattern in _AUTHORITY_PATTERNS:
            m = pattern.search(text)
            if m:
                hits.append(m.group())

        if hits:
            n = len(hits)
            severity = Severity.HIGH if n >= _A_HIGH_THRESHOLD else Severity.MEDIUM
            title = (
                "RAG Context Manipulation — Authority Assertion (Multiple Signals)"
                if severity == Severity.HIGH
                else "RAG Context Manipulation — Authority Assertion"
            )
            snippet = text[:400].strip()
            quoted = "; ".join(repr(h[:60]) for h in hits[:3])
            findings.append(Finding(
                threat_id=ThreatID.T11_RAG_POISONING,
                severity=severity,
                title=title,
                explain=(
                    f"Document contains {n} authority-assertion phrase(s) that attempt "
                    "to override the AI system's knowledge base or claim privileged "
                    f"context: {quoted}."
                ),
                evidence={
                    "matched_phrases": [h[:80] for h in hits[:5]],
                    "snippet": snippet[:250],
                    "malicious_text": snippet[:300],
                    "match_count": n,
                },
                module=self.name,
                confidence=0.85 if severity == Severity.HIGH else 0.75,
                mitre_technique=_MITRE,
                attack_objective=_OBJECTIVE,
            ))

        # ── Sub-B ─────────────────────────────────────────────────────────────
        if getattr(config, "enable_semantic_nn", False):
            ratio, total, unique = _flooding_stats(text)
            if ratio >= _B_DUPLICATE_RATIO_MEDIUM:
                severity = Severity.HIGH if ratio >= _B_DUPLICATE_RATIO_HIGH else Severity.MEDIUM
                findings.append(Finding(
                    threat_id=ThreatID.T11_RAG_POISONING,
                    severity=severity,
                    title="RAG Context Flooding — Repetitive Content Injection",
                    explain=(
                        f"Document contains {total} sentences but only {unique} unique "
                        f"({ratio:.0%} duplication rate). Repetitive content injected into "
                        "a RAG corpus amplifies a malicious phrase's retrieval frequency, "
                        "biasing the AI's responses."
                    ),
                    evidence={
                        "total_sentences": total,
                        "unique_sentences": unique,
                        "duplicate_ratio": round(ratio, 3),
                        "snippet": text[:200].strip(),
                    },
                    module=self.name,
                    confidence=0.80,
                    mitre_technique=_MITRE,
                    attack_objective="Amplify malicious RAG payload via sentence repetition flooding",
                ))

        # ── Sub-C ─────────────────────────────────────────────────────────────
        if getattr(config, "enable_advanced_bert", False):
            for m in _AUTHORITY_BODIES_RE.finditer(text):
                win_start = max(0, m.start() - _C_WINDOW)
                win_end = min(len(text), m.end() + _C_WINDOW)
                window = text[win_start:win_end]
                if _IMPERATIVE_RE.search(window):
                    snippet = text[win_start: min(len(text), win_start + 300)].strip()
                    findings.append(Finding(
                        threat_id=ThreatID.T11_RAG_POISONING,
                        severity=Severity.HIGH,
                        title="RAG Poisoning — False Authority Citation",
                        explain=(
                            f"Document cites '{m.group()[:80]}' as an authority alongside "
                            "an imperative verb within 300 characters. False authority citations "
                            "in RAG corpora manipulate AI systems into treating injected "
                            "instructions as legitimate policy."
                        ),
                        evidence={
                            "authority_claim": m.group()[:100],
                            "snippet": snippet[:250],
                            "malicious_text": snippet[:300],
                        },
                        module=self.name,
                        confidence=0.80,
                        mitre_technique=_MITRE,
                        attack_objective="Impersonate authority body to legitimize injected RAG payload",
                    ))
                    break  # One Sub-C finding per document

        return findings
