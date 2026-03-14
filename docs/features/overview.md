# Features Overview

DocFirewall includes a suite of specialized detectors mapped to specific threat vectors.

## Core Architecture

### Dual-Stage Scanning
1.  **Fast Scan (Byte-Level)**: Instantly identifies structural anomalies, binary signatures, and known bad indicators (like `/JavaScript` tags in PDFs or PE headers) without fully parsing the file. This allows for rapid rejection of obviously malicious files (< 20ms).
2.  **Deep Scan (Parsed Analysis)**: Fully parses the document using [Docling](https://github.com/DS4SD/docling) to extract text, layout, and metadata. This layer applies semantic analysis, PII detection, and complex logic checks.

### Supported Formats
- :material-file-pdf-box: **PDF**: Scans structure (objects, streams), content, and metadata.
- :material-file-word-box: **DOCX**: Scans XML structure, relationships, macros, and embedded media.
- :material-microsoft-powerpoint: **PPTX**: Scans presentation structure, slide relationships, macros, shapes, and embedded payloads.
- :material-microsoft-excel: **XLSX**: Scans workbook structure, sheet relationships, macros, formulas (DDE), and embedded payloads.

## Threat Detection Modules

### 1. Active Content & Malware (T1, T2, T7)
Detects executable code and embedded payloads that could compromise the host system.

-   **Antivirus Integration (T1)**: Connects to ClamAV, VirusTotal, or CLI tools.
-   **Active Content (T2)**: Flags JavaScript, VBA Macros, OLE Objects, and PDF Actions.
-   **Embedded Payloads (T7)**: Identifies embedded binaries (PE, ELF) and suspicious object streams.

### 2. LLM Integrity (T4, T5, T9)
Protects AI models from manipulation.

-   **Prompt Injection (T4)**: Uses regex and semantic analysis (Transformers) to catch jailbreaks.
-   **Ranking Manipulation (T5)**: Identifies keyword stuffing and statistical anomalies.
-   **ATS Manipulation (T9)**: Detects hidden text (white-on-white) and metadata stuffing.

### 3. Evasion & Obfuscation (T3)
-   **Homoglyphs**: Mixed-script characters (Cyrillic vs. Latin) used to spoof keywords.
-   **Invisible Characters**: Zero-Width Joiners and Bidi control characters.

### 4. Infrastructure Protection (T6, T8)
-   **DoS (T6)**: Zip bombs (via expansion ratios and bounds), excessive page counts, recursion loops.
-   **Metadata Injection (T8)**: Buffer overflows and syntax injection in metadata fields.
-   **XXE Defense**: All Office parsers use `defusedxml` to block XML External Entities and mitigate SSRF attacks.

### 5. Configurable Dataset-Agnostic Limits
Instead of relying on hardcoded static heuristics, DocFirewall evaluates proportional risks dynamically using `Limits` (e.g. invisible-character ratio scaling instead of strict counts). Developers can selectively override any regex pattern, timeout, or byte-size limits seamlessly via `ScanConfig.limits`.

### 6. Data Privacy
-   **PII Detector**: Scans for SSN, Email, Phone, Credit Cards.
-   **Secrets Detector**: Finds API Keys, Passwords, and Tokens.
