# DocFirewall

<div align="center" markdown="1">

![DocFirewall Logo](assets/logo_text.png)

**Secure Document Intake for AI Pipelines**

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](https://www.docker.com/)

</div>

---

**DocFirewall** is a zero-trust compliance layer designed to protect Large Language Model (LLM) pipelines, Retrieval-Augmented Generation (RAG) capabilities, and AI Agents from malicious payloads.

Whether you are using **LangChain**, **LlamaIndex**, **Haystack**, or custom agentic workflows, DocFirewall performs strict static analysis and heuristic scanning on **PDF**, **DOCX**, **PPTX**, and **XLSX** files to neutralize threats—such as **Prompt Injection**, **Data Exfiltration**, and **Zip Bombs**—**before** they reach your document parsers, vector databases, or inference engines.

## Key Capabilities

!!! success "Multi-Layered Defense"
    DocFirewall implements a defense-in-depth strategy covering 9 distinct threat vectors, including Prompt Injection, Malware, and Resource Exhaustion.

<div class="grid cards" markdown>

-   :material-bug: **Malware & Virus (T1)**
    ---
    Integration with ClamAV, VirusTotal, and Yara for signature-based detection.

-   :material-script-text: **Active Content (T2)**
    ---
    Detects executable JavaScript, Macros (VBA), OLE objects, and PDF Actions.

-   :material-incognito: **Obfuscation (T3)**
    ---
    Identifies homoglyphs, invisible text, and encryption used to bypass filters.

-   :material-robot-confused: **Prompt Injection (T4)**
    ---
    Flags hidden instructions targeting LLM behavior (e.g., "Ignore previous instructions").

-   :material-trending-up: **Ranking Manipulation (T5)**
    ---
    Detects keyword stuffing and statistical anomalies to artificially boost ranking.

-   :material-server-network-off: **DoS Attacks (T6)**
    ---
    Prevents resource exhaustion via Zip bombs (expansion ratios), excessive page counts, and recursion.

-   :material-shield-check: **Parser Security & Anti-Overfitting**
    ---
    Native protections against XXE / SSRF (`defusedxml`) and fully dynamic constraint injection via `Limits` so rules adapt to your specific data, thwarting statically-overfitted evasion.

-   :material-file-code: **Embedded Payloads (T7)**
    ---
    Scans for embedded binaries (PE, ELF) and malicious object streams.

-   :material-database-lock: **Metadata Injection (T8)**
    ---
    Sanitizes metadata fields against buffer overflows and syntax injection.

-   :material-eye-off: **ATS Manipulation (T9)**
    ---
    Detects SEO poisoning and white-on-white text used to game ranking algorithms.

</div>

## Performance

DocFirewall is optimized for high-throughput environments using a dual-stage scanning architecture:

1.  **Fast Scan**: 10ms-range byte-level analysis for known signatures and structural anomalies.
2.  **Deep Scan**: Full document parsing (powered by Docling) for semantic analysis.

!!! quote "Benchmark Results"
    - **Precision**: 100% (Zero False Positives)
    - **Speed**: $O(n)$ complexity (milliseconds per document for ML heuristic exact-match)
    - **Dataset**: Validated against over **1,000 document artifacts**
    
    *(Performance assessed on v3 Holdout Dataset containing 70+ adversarial samples and 100+ clean benign baseline files)*

## Basic Usage

```python
from doc_firewall import scan

# Scan a document
report = scan("resume.pdf")

if report.verdict == "BLOCK":
    print(f"🚫 Blocked! Score: {report.risk_score}")
    print("Findings:", report.findings)
else:
    print("✅ Safe to process")
```

[Get Started :material-arrow-right:](getting-started/installation.md){ .md-button .md-button--primary }
