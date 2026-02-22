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
    
    H --> K["Risk Scoring"]
    I --> K
    J --> K
    
    K --> L["Final Verdict"]
```

## 1. Input Interface
Documents enter via Python function calls (`scan()`), CLI, or REST API wrappers.

## 2. Pre-Flight
-   **Structure Check**: Verify PDF/DOCX magic bytes.
-   **Size Check**: Enforce `max_mb` limits.
-   **Hashing**: Compute SHA256 for caching/logging.

## 3. Fast Scan (Byte-Level)
Scans the raw binary stream without parsing the document structure.
-   **Speed**: < 20ms.
-   **Goal**: Reject obvious malware, zip bombs, or known signatures immediately.

## 4. Deep Scan (Parsed)
If the file passes Fast Scan, it is parsed into a standardized logical representation (text blocks, key-value metadata).
-   **Parsers**: `docling` (default), `pypdf`, `python-docx`.
-   **OCR**: Optionally enabled for scanned PDFs using RapidOCR.
