from __future__ import annotations
import re
from collections import Counter
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from .injection_normalizer import normalize_for_matching as _norm_for_matching

# Common English function words that legitimately appear at high frequency.
# Exclude these from the ungated 8% frequency check so natural prose
# (e.g. "and" appearing ~8% of tokens in a job description) is not flagged.
_STOP_WORDS: frozenset[str] = frozenset({
    # Articles, conjunctions, prepositions
    "the", "and", "for", "are", "was", "has", "had", "not", "but", "can",
    "its", "our", "all", "one", "two", "any", "who", "how", "his", "her",
    "she", "him", "they", "them", "than", "that", "this", "with", "from",
    "have", "been", "will", "were", "more", "some", "such", "both", "each",
    "what", "when", "then", "also", "into", "onto", "over", "even", "here",
    "well", "your", "just", "only", "very", "most", "much", "less", "few",
    "many", "often", "their", "there", "these", "those", "would", "could",
    "should", "about", "which", "while", "where", "after", "before",
    "other", "under", "above", "through", "between", "during",
    # Pronouns (common in contracts, policies, correspondence)
    "you", "we", "us", "me", "my", "he", "i",
    # Common auxiliaries / modals missed above
    "may", "must", "shall", "does", "did", "use", "per", "via",
})


class ATSManipulationDetector(Detector):
    name = "ats_manipulation"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_ats_manipulation_checks:
            return []

        findings = []
        text = doc.text or ""

        # 1. Keyword Stuffing
        # Check for repeated words in close proximity or high frequency
        if text:
            # Simple frequency check moved to T5 (Ranking Manipulation) to
            # avoid overlapping FPs.
            # ATS manipulation mainly focuses on *hidden* stuffing or
            # mechanical sequence repetition.

            # words = [w.lower() for w in re.findall(r'\b\w{4,}\b', text)]
            # count = Counter(words)
            # ... (removed simple frequency check)

            # Check for repeated sequences (e.g. "Java Java Java Java" or "Best Candidate Best Candidate")
            # We match 1 to 6 words repeated at least 10 times (covers multi-word skill phrases).
            repeated_seq = re.search(r"(\b(?:\w+\s+){1,6})\1{10,}", text, flags=re.IGNORECASE)
            if repeated_seq:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Repeated Keywords Sequence",
                        explain="Detected a sequence of identical words repeated 10+ times.",
                        evidence={"snippet": repeated_seq.group(0)[:50], "malicious_text": repeated_seq.group(0)[:250]},
                        module=self.name,
                        confidence=0.9,
                    )
                )

            # Keyword frequency check — restructured (item 0.10):
            # Previously gated on ats_keywords list, so natural stuffing (e.g.
            # "Python" × 80) was invisible.  New logic:
            #   - Any token > 8% of total → T9 HIGH (ungated)
            #   - Known attack token (in ats_keywords) > 4% → T9 HIGH
            #   - Top-2 tokens together > 15% → T9 MEDIUM (distributed stuffing)
            # Metadata fields (keywords, description) are included in the token pool.
            tokens = [
                t for t in text.lower().split()
                if t.isalpha() and len(t) > 2 and t not in _STOP_WORDS
            ]
            if doc.metadata:
                for key in ("keywords", "description"):
                    val = doc.metadata.get(key, "")
                    if val and isinstance(val, str):
                        extra = [
                            t for t in val.lower().split()
                            if t.isalpha() and len(t) > 2 and t not in _STOP_WORDS
                        ]
                        tokens.extend(extra)
            if len(tokens) >= 25:
                counter = Counter(tokens)
                total = len(tokens)
                top5 = counter.most_common(5)
                most_common, top_freq = top5[0]
                top_ratio = top_freq / total
                ats_kw_set = set(config.ats_keywords)

                # Require a minimum absolute count of 10 to avoid FPs on short
                # documents where a legitimately repeated domain term (e.g. "data"
                # in a data-engineering resume or "performance" in a review doc)
                # hits the 8% ratio purely because the token pool is small.
                if top_ratio > 0.08 and top_freq >= 10:
                    # Any token over 8% with 10+ occurrences is mechanically
                    # repetitive regardless of whether it is a "known attack phrase".
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T9_ATS_MANIPULATION,
                            severity=Severity.HIGH,
                            title="Keyword Stuffing (ATS Manipulation)",
                            explain=(
                                f"Token '{most_common}' appears in {top_ratio:.0%} "
                                "of all words — mechanical repetition indicative of "
                                "ATS score manipulation."
                            ),
                            evidence={
                                "token": most_common,
                                "ratio": round(top_ratio, 3),
                                "malicious_text": most_common,
                            },
                            module=self.name,
                            confidence=0.9,
                        )
                    )
                elif top_ratio > 0.04 and most_common in ats_kw_set:
                    # Known attack token at lower frequency threshold
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T9_ATS_MANIPULATION,
                            severity=Severity.HIGH,
                            title="ATS Injection Token Detected",
                            explain=(
                                f"Known ATS injection token '{most_common}' appears "
                                f"in {top_ratio:.0%} of all words."
                            ),
                            evidence={
                                "token": most_common,
                                "ratio": round(top_ratio, 3),
                                "malicious_text": most_common,
                            },
                            module=self.name,
                            confidence=0.95,
                        )
                    )

                # Distributed stuffing: top-2 tokens together > 15%.
                # Also require each token to appear at least 8 times to avoid
                # FPs on short documents where two domain terms co-occur naturally.
                if len(top5) >= 2:
                    top2_ratio = (top5[0][1] + top5[1][1]) / total
                    if top2_ratio > 0.15 and top5[0][1] >= 8 and top5[1][1] >= 6:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T9_ATS_MANIPULATION,
                                severity=Severity.MEDIUM,
                                title="Distributed Keyword Stuffing (ATS Manipulation)",
                                explain=(
                                    f"Top two tokens ('{top5[0][0]}', '{top5[1][0]}') "
                                    f"together account for {top2_ratio:.0%} of all words "
                                    "— a distributed keyword-stuffing pattern."
                                ),
                                evidence={
                                    "top_tokens": [t for t, _ in top5[:2]],
                                    "combined_ratio": round(top2_ratio, 3),
                                    "malicious_text": f"{top5[0][0]}, {top5[1][0]}",
                                },
                                module=self.name,
                                confidence=0.75,
                            )
                        )

            # B.11: Homoglyph-normalized token analysis.
            # "Рython" (Cyrillic Р) and "python" (Latin p) are different raw
            # tokens but identical after homoglyph normalization.  If the
            # normalized form shows a higher frequency for a token than the raw
            # form does, the author used lookalike characters to dilute apparent
            # repetition and evade raw-token frequency checks.
            norm_text = _norm_for_matching(text)
            norm_tokens = [
                t for t in norm_text.split()
                if t.isalpha() and len(t) > 2 and t not in _STOP_WORDS
            ]
            if len(norm_tokens) >= 25:
                norm_counter = Counter(norm_tokens)
                norm_most_common, norm_freq = norm_counter.most_common(1)[0]
                norm_ratio = norm_freq / len(norm_tokens)
                raw_ratio = counter.get(norm_most_common, 0) / total
                # Only flag when normalization reveals significantly higher frequency
                # and the token appears enough times to exclude short-document noise.
                if norm_ratio > 0.08 and norm_freq >= 10 and norm_ratio - raw_ratio > 0.03:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T3_OBFUSCATION,
                            severity=Severity.HIGH,
                            title="Homoglyph ATS Keyword Stuffing",
                            explain=(
                                f"Token '{norm_most_common}' appears in "
                                f"{norm_ratio:.0%} of words after homoglyph "
                                f"normalization but only {raw_ratio:.0%} in raw text. "
                                "Cyrillic or Greek lookalikes used to evade raw-token "
                                "frequency checks (T3+T9)."
                            ),
                            evidence={
                                "normalized_token": norm_most_common,
                                "normalized_ratio": round(norm_ratio, 3),
                                "raw_ratio": round(raw_ratio, 3),
                                "malicious_text": norm_most_common,
                            },
                            module=self.name,
                            confidence=0.85,
                        )
                    )

        # 2. Hidden Text / Font Size 0 (T9)
        if doc.metadata and "hidden_text" in doc.metadata:
            ht = doc.metadata["hidden_text"]
            if ht:
                # If list, join.
                if isinstance(ht, list):
                    ht = " ".join(ht)

                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Hidden Text Detected",
                        explain=(
                            "Found text hidden via 'vanish' property or "
                            "white-on-white/size-0 formatting."
                        ),
                        evidence={"snippet": ht[:100], "malicious_text": ht[:250]},
                        module=self.name,
                        confidence=0.95,
                    )
                )

        # Check vanilla vanish attribute if not parsed into hidden_text but flagged
        if doc.metadata and doc.metadata.get("has_hidden_tags"):
            findings.append(
                Finding(
                    threat_id=ThreatID.T9_ATS_MANIPULATION,
                    severity=Severity.MEDIUM,
                    title="Hidden Text Tags Detected",
                    explain="Found XML tags indicating hidden text (<w:vanish/>).",
                    evidence={"tag": "w:vanish"},
                    module=self.name,
                    confidence=0.9,
                )
            )
        # If the analyzer populated hidden_text (e.g. from XML)
        if doc.docx and "hidden_text" in doc.docx:
            hidden = doc.docx["hidden_text"]
            if hidden:
                # If list or string
                content_len = len(str(hidden))
                if content_len > 0:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T9_ATS_MANIPULATION,
                            severity=Severity.MEDIUM,
                            title="Hidden Text Detected",
                            explain=(
                                "Document contains text marked as hidden, often "
                                "used for ATS manipulation."
                            ),
                            evidence={"length": content_len, "malicious_text": str(hidden)[:250]},
                            module=self.name,
                            confidence=0.9,
                        )
                    )

        # D.17: Per-section frequency check.  A resume that cleanly mentions
        # "Python" at 5% globally but stuffs it 30\u00d7 into a single hidden table
        # dilutes below the 8% global threshold.  Split into sections by page
        # break / heading / large gap and re-run the frequency check at a
        # higher threshold (12%) so a single poisoned section fires.
        if text and len(text) > 1500:
            # Section boundaries: form-feed, double-newline, heading marker
            sections = re.split(
                r"(?:\f|\n{2,}|^#{1,6}\s+|<\s*h[1-6]\s*>)",
                text,
                flags=re.MULTILINE,
            )
            for sec_idx, sec in enumerate(sections):
                if len(sec) < 800:
                    continue  # too small to be meaningful
                sec_tokens = [
                    t for t in sec.lower().split()
                    if t.isalpha() and len(t) > 2 and t not in _STOP_WORDS
                ]
                if len(sec_tokens) < 30:
                    continue
                sec_counter = Counter(sec_tokens)
                top_token, top_freq = sec_counter.most_common(1)[0]
                sec_ratio = top_freq / len(sec_tokens)
                # Higher per-section threshold (12%) avoids FPs on legitimate
                # short keyword-dense sections (skills lists).  Require 10
                # absolute occurrences.
                if sec_ratio > 0.12 and top_freq >= 10:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T9_ATS_MANIPULATION,
                            severity=Severity.MEDIUM,
                            title=f"Per-Section Keyword Stuffing (section #{sec_idx})",
                            explain=(
                                f"In section #{sec_idx} of {len(sections)}, "
                                f"token '{top_token}' appears in {sec_ratio:.0%} "
                                f"of {len(sec_tokens)} tokens. Per-section "
                                "concentration of one keyword is a stuffing "
                                "pattern that the global frequency check dilutes."
                            ),
                            evidence={
                                "subtype": "per_section_stuffing",
                                "section_index": sec_idx,
                                "section_count": len(sections),
                                "token": top_token,
                                "section_ratio": round(sec_ratio, 3),
                                "occurrences": top_freq,
                                "malicious_text": top_token,
                            },
                            module=self.name,
                            confidence=0.78,
                        )
                    )
                    break  # one per-section finding per document

        # 3. High Zero Width / Bidi characters (used for hiding ATS keywords)
        ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\ufeff"}
        if text:
            zw_count = sum(1 for ch in text if ch in ZERO_WIDTH)
            text_len = max(1, len(text))
            if (
                zw_count >= 50
                and (zw_count / text_len) > config.obfuscation_zw_threshold_ratio
            ):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.HIGH,
                        title="Hidden ATS Text via Zero-Width Characters",
                        explain="High number of zero-width characters used to hide ATS text.",
                        evidence={"zw_count": zw_count, "malicious_text": "Zero-width sequence detected"},
                        module=self.name,
                        confidence=0.9,
                    )
                )

        return findings
