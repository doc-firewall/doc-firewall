import logging
from typing import List

from .base import Detector
from ..report import Finding
from ..config import ScanConfig
from ..analyzers.base import ParsedDocument
from ..enums import ThreatID, Severity

logger = logging.getLogger(__name__)

# Hard caps so an adversarial document (e.g. a malicious spreadsheet with tens
# of thousands of cells) cannot blow up memory. Without these, fitting TF-IDF
# over every "sentence" built an (n_sentences x vocab) matrix; densifying it
# allocated n_sentences*vocab*8 bytes — ~150 GB on a stuffed workbook.
_MAX_TFIDF_SENTENCES = 2000   # bounds the matrix row count
_MAX_TFIDF_FEATURES = 20000   # bounds the vocabulary (column count)


class AdvancedATSNLPDetector(Detector):
    name = "advanced_ats_nlp"

    def __init__(self) -> None:
        self._vectorizer = None
        self._sem_model = None  # B.9: sentence-transformers model (lazy-loaded)

    def _init_tfidf(self) -> None:
        if self._vectorizer is None:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                # Configure to find high frequency keyword n-grams. max_features
                # bounds the vocabulary so the feature space can't explode on
                # adversarial input.
                self._vectorizer = TfidfVectorizer(
                    stop_words='english',
                    ngram_range=(1, 3),
                    max_features=_MAX_TFIDF_FEATURES,
                )
            except ImportError:
                logger.error("scikit-learn is not installed.")

    def _init_semantic(self, config: ScanConfig) -> None:
        """Lazy-load the sentence-transformer model (reuses injection_nn model)."""
        if self._sem_model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._sem_model = SentenceTransformer(config.nn_model_name)
            except Exception:
                self._sem_model = None

    def _detect_paraphrase_stuffing(
        self, sentences: list[str], config: ScanConfig
    ) -> list[Finding]:
        """B.9: Cluster sentence embeddings; flag if > 40% are semantic duplicates.

        Synonym rotation ("experienced developer / skilled programmer / seasoned coder")
        defeats TF-IDF and Jaccard but not cosine-similarity clustering over embeddings.
        """
        findings: list[Finding] = []
        if not config.enable_semantic_nn:
            return findings

        self._init_semantic(config)
        if self._sem_model is None:
            return findings

        sample = sentences[:100]  # cap to avoid OOM on adversarial documents
        if len(sample) < 5:
            return findings

        try:
            import numpy as np

            embeddings = self._sem_model.encode(sample, convert_to_numpy=True)
            norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
            embeddings = embeddings / np.maximum(norms, 1e-10)
            sim_matrix = embeddings @ embeddings.T  # pairwise cosine similarity

            # Union-find clustering at similarity ≥ 0.85
            n = len(sample)
            parent = list(range(n))

            def find(x: int) -> int:
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            for i in range(n):
                for j in range(i + 1, n):
                    if float(sim_matrix[i, j]) >= 0.85:
                        ri, rj = find(i), find(j)
                        if ri != rj:
                            parent[ri] = rj

            from collections import Counter
            cluster_sizes = Counter(find(i) for i in range(n))
            largest = cluster_sizes.most_common(1)[0][1]
            ratio = largest / n

            if ratio > 0.4:
                severity = Severity.CRITICAL if ratio > 0.6 else Severity.HIGH
                findings.append(
                    Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=severity,
                        confidence=round(float(ratio), 2),
                        title="Semantic Paraphrase Stuffing Detected",
                        explain=(
                            f"{int(ratio * 100)}% of sentences are semantically "
                            "equivalent (cosine similarity ≥ 0.85). Synonym rotation "
                            "evades exact-token frequency checks — a sophisticated "
                            "ATS manipulation technique."
                        ),
                        evidence={
                            "semantic_cluster_ratio": round(ratio, 3),
                            "largest_cluster_size": largest,
                            "total_sentences": n,
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Semantic paraphrase clustering failed: %s", exc)

        return findings

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
            # Cap the row count: an adversarial document with tens of thousands
            # of "sentences" would otherwise build a huge matrix. Keyword
            # stuffing is still obvious within the first few thousand sentences.
            sentences = sentences[:_MAX_TFIDF_SENTENCES]

            tfidf_matrix = self._vectorizer.fit_transform(sentences)
            feature_names = self._vectorizer.get_feature_names_out()

            # Per-term max TF-IDF across the document. Computed on the SPARSE
            # matrix — never densified — so we never allocate an
            # (n_sentences x vocab) array. `.max(axis=0)` returns a 1 x vocab
            # sparse row; vocab is bounded by max_features.
            import numpy as np
            max_scores = np.asarray(tfidf_matrix.max(axis=0).todense()).ravel()

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
                
                # If more than 40% of consecutive sentences are 95% identical that
                # is ATS stuffing — sentences are copy-pasted to pad keyword density.
                # Reclassified from T5 (ranking) to T9 (ATS manipulation) because
                # this pattern targets ATS score inflation, not RAG ranking.
                if float(high_jaccard_count) / len(sentences) > 0.4:
                     findings.append(Finding(
                        threat_id=ThreatID.T9_ATS_MANIPULATION,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        title="Semantic Sentence Repetition (ATS Stuffing)",
                        explain="Jaccard similarity detected abnormally high repetition of context/role text — characteristic of copy-pasted keyword stuffing.",
                        evidence={"malicious_text": sentences[0][:250]}
                    ))

            # B.9: Semantic paraphrase stuffing — synonym rotation evades TF-IDF
            # and Jaccard checks; embedding clustering catches it.
            findings.extend(
                self._detect_paraphrase_stuffing(sentences, config)
            )

        except Exception as e:
            logger.warning(f"Advanced ATS NLP failed: {e}")

        return findings