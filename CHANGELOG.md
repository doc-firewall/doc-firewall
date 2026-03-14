# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
