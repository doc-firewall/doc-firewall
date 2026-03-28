# Advanced ML & Heuristic Scanners

Introduced in `v0.3.0`, DocFirewall supports highly robust **Advanced Local Machine Learning** and **Heuristic Detectors**. These modules provide massive upgrades to accuracy for zero-day threats and polymorphic text mutations while operating **entirely offline** without sending data to external APIs.

Because these modules invoke robust numerical matching and NLP classification, they are completely opt-in to preserve sub-millisecond execution speeds for users who do not rely on AI integrity filtering.

## 1. Advanced Prompt Injection (Aho-Corasick & BERT)
*Maps to: Threat Model T4 (Prompt Injection & Jailbreaks)*

This engine drastically improves detection of explicit and polymorphic LLM jailbreaks.

**Aho-Corasick Fast Filtering:**
Uses the `pyahocorasick` library to construct a finite-state automaton, enabling $O(n)$ ultra-fast multiplexed regex scanning on heavily documented jailbreaks. 
Instead of checking strings sequentially, it simultaneously maps thousands of known payloads into memory, allowing real-time blacklisting.

**Local Deep Learning (BERT Pipeline):**
A zero-day LLM-classification strategy via `sentence-transformers` running standard architectures (e.g., `ProtectAI/deberta-v3-base-prompt-injection-v2`).
By running ML locally and breaking the document logically into sequence chunks, we stop advanced polymorphic and nuanced "ignore your instructions" commands which evade statistical analysis.

## 2. Term Frequency & ATS Analysis (TF-IDF & Jaccard)
*Maps to: Threat Model T5 (Ranking Manipulation) & T9 (ATS Manipulation)*

A mathematical assessment determining CV/resume integrity and text-stuffing.

**TF-IDF Matrix:**
Leverages `scikit-learn` to calculate statistical vector drift. It highlights specific strings hidden internally that attempt to overwhelm applicant tracking systems by repeating keywords invisible to the human eye, scoring their variance proportionally.

**Jaccard Distance Mapping:**
Evaluates mathematical distance and overlapping duplication across sliding windows of sentences to calculate repetition anomalies efficiently.

## 3. High-Fidelity Secrets (Shannon Entropy)
*Maps to: Data Exfiltration / Threat Model T7 / Privacy Scans*

A decoupling from strict regex limits. Standard regex fails on novel, high-complexity API Keys or temporary JWT signatures. 
Our advanced scanner evaluates continuous alphanumeric, symbol-rich block segments without spaces using the standard mathematical **Shannon Entropy** limit ($H(X) > 5.5$).
If text string entropy exhibits cryptographic chaos levels of randomness, it is structurally identified as a high-security access secret.

## Configuration & Usage
To enable these modules, edit your configuration:

```python
from doc_firewall import ScanConfig, Scanner

config = ScanConfig(
    enable_advanced_ahocorasick=True,
    enable_advanced_bert=True,       # Will dynamically download/load the classifier
    enable_advanced_tfidf=True,
    enable_credential_entropy=True,
    
    # Custom pipeline model path supported
    bert_model_path="ProtectAI/deberta-v3-base-prompt-injection-v2"
)
```