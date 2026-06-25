---
title: Architecture — Two-Stage Document Scanning Pipeline
description: DocFirewall uses a two-stage pipeline: a fast byte-level scan (<10ms) followed by a deep semantic scan powered by Docling. Learn how the detection pipeline processes PDF, DOCX, PPTX, XLSX, RTF, HTML, legacy Office, CSV/TSV, OpenDocument, and plain-text files.
---

# Architecture

DocFirewall uses a pipeline architecture to process documents efficiently.

```mermaid
graph TD
    A["Input File"] --> B["Pre-Flight Checks"]
    B --> C{"Fast Scan"}
    C -->|"Critical Threat Found"| D["Block"]
    C -->|"Safe"| E["Deep Scan"]
    E --> F["Parsing (Docling)"]
    F --> G["Detector Pipeline"]
    
    subgraph Detectors ["Detectors"]
        H["T2 Active Content"]
        I["T4 Prompt Injection"]
        J["T8 Metadata"]
    end
    
    G --> H
    G --> I
    G --> J
    
    H --> K["Findings (each carries verdict_class)"]
    I --> K
    J --> K

    K --> L["Verdict Resolver"]
    L --> M["Final Verdict (ALLOW / FLAG / BLOCK)"]
    K --> N["Risk Score (analytics)"]
```

The verdict is derived from finding **classes**, not from the risk score. Each finding produced by a detector carries a `verdict_class` of `BLOCK` (definitive evidence — YARA hit, EICAR, `javascript:` URI, embedded PE/ELF, etc.), `REVIEW` (heuristic / suggestive signal), or `INFO` (recorded for audit only). The resolver returns `BLOCK` if any finding is BLOCK-class, otherwise `FLAG` if any is REVIEW-class, otherwise `ALLOW`. The risk score is computed in parallel for analytics dashboards but does not gate the verdict. See [Risk Scoring & Verdict Model](risk-scoring.md) for details.

## 1. Input Interface
Documents enter via Python function calls (`scan()`), CLI, or REST API wrappers.

## 2. Pre-Flight
-   **Structure Check**: Verify PDF/DOCX/PPTX/XLSX magic bytes.
-   **Size Check**: Enforce `max_mb` limits.
-   **Hashing**: Compute SHA256 for caching/logging.

## 3. Fast Scan (Byte-Level)
Scans the raw binary stream without parsing the document structure.
-   **Speed**: < 20ms.
-   **Goal**: Reject obvious malware, zip bombs, or known signatures immediately.

## 4. Deep Scan (Parsed)
If the file passes Fast Scan, it is parsed into a standardized logical representation (text blocks, key-value metadata).
-   **Parsers**: `docling` (default, with OCR disabled — text-based PDFs only), `pypdf`, `python-docx`.
-   **OCR**: Not used by default. DocFirewall scans the text layer; OCR is not required for prompt injection or hidden-text detection.

## 5. Offline Intelligence (Zero-API Execution)
All processing—including obfuscation normalization (Layer 0), Aho-Corasick phrase matching (Layer 1, < 1 ms), regex fuzzy patterns (Layer 2, < 1 ms), sliding-window BERT sequence classification (Layer 3, ~50 ms with local DeBERTa weights), and optional semantic nearest-neighbour matching (Layer 4)—runs **strictly locally on CPU/GPU architecture**.
There are **zero external API calls**, protecting PII immediately by default and maintaining strict data residency compliance without relying on third-party services.
