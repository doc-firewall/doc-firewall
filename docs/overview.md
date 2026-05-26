---
title: Overview — DocFirewall Capabilities & Threat Coverage
description: Overview of DocFirewall's 12 threat vectors (T1–T12), multi-layered defense architecture, and benchmark performance. Covers prompt injection, malware, obfuscation, indirect injection, RAG poisoning, social engineering, and ATS manipulation detection.
---

# DocFirewall

<div align="center" markdown="1">

![DocFirewall Logo](assets/logo_text.webp)

**Document Security Scanner for AI & RAG Pipelines**

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue)](https://www.docker.com/)

</div>

---

**DocFirewall** is a specialized security library designed to deeply scan and sanitize modern document formats (PDFs and ZIP-based Office files like DOCX, PPTX, and XLSX) against hidden threats. It goes beyond standard malware scanning by deeply parsing the structural content of files to detect advanced attack vectors such as prompt injection, credential and secrets leakage, embedded payloads, hidden text, and denial-of-service (Zip Bomb) attempts. The engine allows for highly configurable profiles, including the ability to apply custom YARA rules, utilize machine-learning-based detectors, and integrate seamlessly with traditional antivirus engines like ClamAV. Upon scanning a doc, it outputs a comprehensive risk score, a definitive safety verdict, and structured forensic evidence pinpointing the exact location of any malicious findings. Ultimately, it acts as a robust first line of defense for applications that need to safely ingest user-uploaded documents and feed clean telemetry to security operation centers (SIEMs).

In the context of DocFirewall, an **embedded payload** refers to hidden executable code or malicious components smuggled inside an otherwise normal-looking document. Attackers frequently use techniques like embedding raw scripts, Windows executables (PE files), or Linux binaries (ELF files) within the deep structural layers of PDFs or Office files. DocFirewall detects these threats by tearing apart the document's internal objects and scanning for distinct binary signatures or unnatural entropy levels. It actively flags recognizable malware headers (like the "MZ" stub for Windows) and unusually large blocks of Base64 or Hex-encoded data, which are often used to obfuscate a smuggled virus. By exposing these hidden elements, the engine prevents the document from acting as a Trojan horse that silently drops malware when opened.

## Key Capabilities

!!! success "Multi-Layered Defense"
    DocFirewall implements a defense-in-depth strategy covering 12 distinct threat vectors (T1–T12), including Prompt Injection, Malware, Indirect/Multi-Hop Injection, RAG Poisoning, Social Engineering, and Resource Exhaustion.

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

-   :material-link-variant: **Indirect / Multi-Hop Injection (T10)**
    ---
    Flags external-reference + fetch-instruction co-occurrence and agent tool-call schemas pointing at remote payloads (`data:`/`smb:`/UNC/raw-GitHub URIs).

-   :material-database-alert: **RAG / KB Poisoning (T11)**
    ---
    Detects authority-assertion patterns, sentence-duplication flooding, false citations, and chunk-boundary split injection targeting vector stores.

-   :material-account-alert: **Social Engineering (T12)**
    ---
    Tri-signal urgency/authority/action-demand co-occurrence with HIGH overrides for credential harvesting, fake legal threats, and crypto / gift-card / tech-support scams.

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
