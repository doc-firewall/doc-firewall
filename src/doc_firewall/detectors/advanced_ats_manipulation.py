import logging
from typing import List

from .base import Detector
from ..report import Finding
from ..config import ScanConfig
from ..analyzers.base import ParsedDocument
from ..enums import ThreatID, Severity

logger = logging.getLogger(__name__)

class AdvancedATSNLPDetector(Detector):
    name = "advanced_ats_nlp"

    def __init__(self):
        self._vectorizer = None

    def _init_tfidf(self):
        if self._vectorizer is None:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                # Configure to find high frequency keyword n-grams
                self._vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 3))
            except ImportError:
                logger.error("scikit-learn is not installed.")

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        findings = []
        if not config.enable_advanced_tfidf:
            return findings

        full_text = getattr(doc, 'text', '') or ""
        if len(full_text.split()) < 50:
            return findings

        self._init_tfidf()
        if not self._vectorizer:
            return findings

        try:
            # TF-IDF for statistical drift / keyword stuffing
            # We fit on the document's own sentences to find wildly repetitive phrases
            sentences = [s.strip() for s in full_text.split('.') if len(s.strip()) > 10]
            if len(sentences) < 5:
                return findings
                
            tfidf_matrix = self._vectorizer.fit_transform(sentences)
            feature_names = self._vectorizer.get_feature_names_out()
            dense = tfidf_matrix.todense()
            
            # Find the max tf-idf score for any given term across the document
            # Abnormally high scores mean severe keyword stuffing
            max_scores = dense.max(axis=0).tolist()[0]
            
            # Pair scores with features
            phrase_scores = [(feature_names[i], max_scores[i]) for i in range(len(feature_names))]
            phrase_scores.sort(key=lambda x: x[1], reverse=True)

            top_phrase = None
            top_score = 0.0
            for phrase, score in phrase_scores:
                # Ignore singleton header terms like "education" or names that can
                # score 1.0 in benign resumes when fitting on a single document.
                if " " not in phrase:
                    continue
                if full_text.lower().count(phrase.lower()) < 2:
                    continue
                top_phrase, top_score = phrase, score
                break

            # Usually tf-idf maxes out around 0.6-0.8 for normal documents. If a
            # repeated multi-word phrase hits ~1.0, it's strong evidence of stuffing.
            if top_phrase and top_score > 0.999:
                findings.append(Finding(
                    threat_id=ThreatID.T9_ATS_MANIPULATION,
                    severity=Severity.HIGH,
                    confidence=round(float(top_score), 2),
                    title="Keyword Stuffing Drift",
                    explain=f"TF-IDF detected severe keyword stuffing drift. Top anomalous phrase: '{top_phrase}'",
                    evidence={"malicious_text": top_phrase}
                ))

            # Jaccard calculations for context deviation
            # Example: check if document sentences are repeating heavily vs each other
            if len(sentences) > 10:
                def jaccard_similarity(s1, s2):
                    set1 = set(s1.lower().split())
                    set2 = set(s2.lower().split())
                    if not set1 or not set2: return 0
                    return len(set1.intersection(set2)) / float(len(set1.union(set2)))

                # Sample adjacent sentences
                high_jaccard_count = 0
                for i in range(len(sentences) - 1):
                    sim = jaccard_similarity(sentences[i], sentences[i+1])
                    if sim > 0.95:  # tightened from 0.8
                        high_jaccard_count += 1
                
                # If more than 40% of consecutive sentences are 95% identical, that's ranking spam!
                if float(high_jaccard_count) / len(sentences) > 0.4:
                     findings.append(Finding(
                        threat_id=ThreatID.T5_RANKING_MANIPULATION,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        title="Semantic Repetition",
                        explain="Jaccard similarity detected abnormally high repetition of context/role text.",
                        evidence={"malicious_text": sentences[0][:250]}
                    ))

        except Exception as e:
            logger.warning(f"Advanced ATS NLP failed: {e}")

        return findings