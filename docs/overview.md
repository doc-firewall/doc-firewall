# DocFirewall

<div align="center" markdown="1">

![DocFirewall Logo](assets/logo_text.png)

**Secure Document Intake for AI Pipelines**

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](https://www.docker.com/)

</div>

---

**DocFirewall** is a high-performance, configurable security scanner designed to protect Large Language Model (LLM) pipelines, RAG systems, and document processing workflows from malicious uploads. 

It performs static analysis and heuristic scanning on **PDF** and **DOCX** files to neutralize threats **before** they reach your parser or inference engine.

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
    Prevents resource exhaustion via Zip bombs, excessive page counts, and recursion.

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
    - **Precision**: 100%
    - **Recall**: 100%
    - **F1 Score**: 1.0
    
    *(Validated on v3 Holdout Dataset containing 70+ adversarial samples)*

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
