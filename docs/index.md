---
hide:
  - navigation
  - toc
---

# Welcome to DocFirewall

**DocFirewall** is a security library designed to scan documents (PDF, DOCX) for hidden threats that bypass traditional antivirus. It focuses on threats relevant to Modern AI/LLM pipelines (Prompt Injection, Jailbreaks) and enterprise document processing.

## Key Features

-   **Comprehensive Threat Model**: Detects 9 distinct threat vectors (T1-T9), including Obfuscation, Prompt Injection, and Layout Manipulation.
-   **Deep Inspection**: Parses document structure to find hidden payloads in metadata, invisible text, and embedded objects.
-   **Extensible Architecture**: Plug-and-play support for custom detectors, including YARA rules and ML models.
-   **Docker Ready**: Full containerized benchmark suite for rigorous security validation.

## Threat Coverage (T1-T9)

The system is evaluated against a rigorous dataset of **410 test cases** covering:

1.  **T1: Malware**: Traditional exploits and viruses (via Antivirus integration).
2.  **T2: Active Content**: Macros, JavaScript, and embedded executables.
3.  **T3: Obfuscation**: Hidden text, white-on-white text, font manipulation.
4.  **T4: Prompt Injection**: Text designed to manipulate LLM behavior.
5.  **T5: Ranking Manipulation**: Keyword stuffing to bias RAG search results.
6.  **T6: Denial of Service**: Zip bombs, deeply nested objects, and recursive streams.
7.  **T7: Embedded Payloads**: Files hidden within files (Polyglots).
8.  **T8: Metadata Injection**: Malicious XMP/Exif tags.
9.  **T9: ATS Manipulation**: Layout tricks to deceive applicant tracking systems.

## Quick Links

-   [Installation Command](getting-started/installation.md)
-   [Running Benchmarks](development/benchmarking.md)
-   [API Reference](api/scanner.md)
