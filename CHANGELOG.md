# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.8] - 2026-05-02

### Fixed
- **T1 EICAR detection (PDF/XLSX):** `YaraDetector` EICAR signature check was gated behind `enable_yara=False` (the default), causing 100% miss rate on T1 malware in PDF and XLSX. Moved the EICAR check before the `enable_yara` guard so it always runs.
- **T3/T5/T6/T9 detection in PDF:** Added detection for PDF white-on-white stealth text (`1 1 1 rg` color operator) in `fast_scan_pdf`. Attackers rendered adversarial content in white text on a white background — invisible to humans but extractable by parsers.
- **T7 detection in XLSX (hex-encoded payloads):** `EmbeddedPayloadDetector` only matched large base64 blobs; added pattern matching for hex-encoded binary file magic numbers (`4D5A` PE, `7F454C46` ELF) in document text and metadata.
- **T9 detection in XLSX/PDF (ATS manipulation):** `ATSManipulationDetector` now includes `keywords` and `description` metadata fields in the token frequency analysis; attacks routed through metadata were not counted. Lowered minimum token threshold from 50 → 25 to handle short documents with clear keyword stuffing.

## [0.3.0] - 2026-03-28

### Added
- **Advanced Local ML Scanners:** Introduced powerful offline Machine Learning / NLP modules.
- **Aho-Corasick Algorithm:** Implemented finite-state automaton for O(n) exact string matching on known `T4_PROMPT_INJECTION` payloads.
- **Local BERT Pipeline:** Embedded zero-day deep learning text-classification (`huggingface`, `sentence-transformers`) for detecting polymorphic prompt and ATS manipulations.
- **TF-IDF & Jaccard Similarity:** Leveraged `scikit-learn` to identify keyword stuffing and statistical term deviations (`T5_RANKING_MANIPULATION` and `T9_ATS_MANIPULATION`).
- **Shannon Entropy Scoring:** Integrated structured mathematical calculations to detect hardcoded API Keys, Passwords, and Data Exfiltration streams.
- **Dynamic Feature Flags:** Added granular explicit opt-ins via `ScanConfig` (`enable_advanced_ahocorasick`, `enable_advanced_bert`, etc.) safely defaulting to False for backwards compatibility.
- **Examples:** Included isolated feature scripts (`08_advanced_ml_scanners.py`) and fully stacked maximum security scripts (`09_recommended_advanced_scan.py`).

### Changed
- Shifted project distribution state to `Development Status :: 5 - Production/Stable`.
- Fixed several legacy test expectations that failed under optimized false-positive bounds tuning.
- Resolved top-level GitHub Actions scorecard vulnerability by adopting strict job-level `contents` permissions on PyPI build matrix.
- `Atheris` pipeline dependencies synchronized/bumped to `3.0.0`.

## [0.2.0] - 2026-03-08

### Added
- **PPTX Support:** Full layout mapping, recursive embedded object tracking, and metadata extraction for Microsoft PowerPoint presentations.
- **XLSX Support:** Full spreadsheet parsing, cell value extraction, and DDE link (Active Content) detection for Microsoft Excel files.
- **T2 (Active Content):** Refined scanning capabilities to natively track dynamic external payload queries in `.pptx` and `.xlsx`.
- **T3 (Obfuscation):** Added dynamic ratio thresholding for hidden zero-width unicode characters specific to nested cells/slides.
- **T8 (Metadata Injection):** Injected deep inspection support to flag embedded SQL queries and malicious command strings hidden in format properties.
- **Overlapping Threat Architecture:** Allowed internal detection schemas to transparently track dual-state threat classifications (i.e., `T9_ATS_MANIPULATION` when utilizing `T3_OBFUSCATION`).

### Changed
- Refactored `Scanner()` initialization to consistently load the complete suite of detector arrays globally (resolving missing isolated threat models).
- Enhanced exact threshold scaling across `text_obfuscation.py` to heavily reduce False Negatives.

## [0.1.0] - 2026-02-22

### Added
- Initial Open Source release of the `doc_firewall` scanning engine.
- Supported core structures: Microsoft Word (`.docx`) and Adobe Standard (`.pdf`).
- Configured 9 Primary Threat Models (`T1` through `T9`).
- Incorporated ClamAV integration functionality.
- Shipped MkDocs documentation bindings.
