# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.3] - 2026-05-23

### Fixed

- **PDF text false-negatives (~40 documents)** — when Docling returned truncated/partial text for a PDF, the regex-fallback extraction was discarded. The PDF parser now unions the fallback text with the Docling output (preferring the longer / non-empty result), so injection and embedded-payload content past Docling's truncation point is no longer missed.
- **T7 base64-embedded payloads silently undetected** — `embedded_payload.py` was missing `import base64`; every `base64.b64decode` call raised `NameError` that a bare `except` swallowed, making the entire decode-and-flag path dead code. Import restored.
- **T9 / T3 homoglyph detection silently disabled** — `ats_manipulation.py` raised `UnboundLocalError: counter` in the homoglyph branch (`counter` / `total` referenced before assignment). Hoisted above the guarding block.
- **First scan bypassed all deep-scan detectors** — one-time cold-start model/automaton initialization pushed the first document past the 5 s detector-stage budget, so it returned with `detectors_timed_out` and zero deep findings. The detector-stage timeout default is raised to absorb warm-up (see Changed).

### Changed

- **Short base64 segments now decoded before T4 / T3 matching** — `advanced_prompt_injection.py` decodes embedded base64 tokens and appends the plaintext to the normalized text before matching, closing a standard-mode T3 obfuscation gap (previously only the ML / defense-in-depth path caught it). Reuses the existing tuned matchers — no new false-positive heuristic.
- `limits.detectors_timeout_ms` default raised 5000 → 30000 ms.

### Documentation

- Corrected all bundled `examples/` scripts — invalid `Finding.rule_id`, and rebuilt the examples index for T1–T12.
- Corrected the published docs: invalid `profile="fast"`, JSON `"file"` → `"file_path"`, non-existent `T7_SENSITIVE_PII` policy weight → `T8_METADATA_INJECTION`, wrong custom-phrase YAML key (`phrases:` → `custom_phrases:`), default `flag` threshold (0.35 → 0.25), `black`/`mypy` → `ruff`, stale CLI output sample, and YARA rule count (30+ → 53).

## [0.4.2] - 2026-05-17

### Fixed

- **T6 false-positive on slow benign documents** — detector-stage timeout no longer emits a `T6_DOS` finding; records `report.metadata["detectors_timed_out"]` and logs a warning instead. Real DoS is still caught by fast-scan / parse-stage T6 paths.
- **Docling subprocess spawned unnecessarily for non-PDF formats** — `convert_with_docling` now skips the subprocess for non-`.pdf` sources; DOCX is handled by the fallback parser and was never a valid Docling input.

## [0.4.1] - 2026-05-16

### Added

- **3 new formats (9 total)** — legacy OLE `.doc`/`.xls`/`.ppt` (VBA-stomping / `vbaProject.bin`), CSV/TSV (formula injection, DDE), OpenDocument `.odt`/`.ods`/`.odp` (macro:// CVE-2023-2255).
- PDF `/JBIG2Decode` (CVE-2021-30860), `/RichMedia`, `/3D`, `/GoToE`; Excel `veryHidden` + inline XLM; HTML SVG/MathML/CSS-`javascript:`/atob+Blob smuggling; Mach-O/WASM/ISO/RAR/7z embedded-binary signatures; PDF annotation subtypes + AcroForm `/V`/`/DV` field defaults; embedded media metadata (ID3/MP4/RIFF).
- Evasion resistance — math-script + reversed-text matching, expanded Unicode confusables, separator normalization, edit-distance-1 fuzzy matching, multilingual phrase set expanded to 22 languages.
- Broader indirect-injection URI vocabulary (`data:`/`smb:`/UNC/raw-GitHub fire HIGH); RAG chunk-boundary split detection; crypto / gift-card / tech-support social-engineering patterns; opt-in QR-code decoding (quishing) + PDF/ODF image OCR.
- Page-tree & slide-master cycle DoS detection; PDF `/ActualText` overlay density; per-section ATS keyword check; risk-model calibration script.
- Detector regex/automaton now pre-compiled at `Scanner` construction (first scan no longer slower than steady-state); 220-document benign corpus with SHA-256 manifest and CI false-positive gate (≤1% balanced, ≤3% strict). Test suite 192 → 301.

### Changed

- **PII detector** now wired into the Scanner (was defined but unused); threat ID corrected `T2` → `T8`; HIPAA Safe-Harbor identifier subset + XMP metadata scanning added.
- **Precision hardening (benign-corpus FP rate 78.6% → 0.00%)** — perplexity-based GCG-suffix detection is now opt-in / default off (character statistics cannot separate adversarial suffixes from dense legal formatting); fuzzy matching restricted to longer multi-word phrases; social-engineering urgency+authority pair now also requires an action demand.
- YARA ruleset 38 → 53 rules with `meta.cve`/`meta.mitre`.

### Fixed

- Built-in YARA ruleset was uncompilable on yara-python ≥ 4.5 (`(?:…)`, `/m`, `($a or $b) in (range)`) — silently disabling YARA. Rewritten to valid syntax.

## [0.4.0] - 2026-05-10

### Added

- **New format support** — RTF (OLE objects, `\bin` streams, `\fldinstr` macros, `\v` hidden text) and HTML (`<script>`, inline event handlers, CSS hidden text) added alongside existing PDF/DOCX/PPTX/XLSX. Macro-enabled Office templates (`.dotm`, `.xltm`, `.potm`, `.xlsm`, `.pptm`) now accepted and flagged T2 by default.
- **T10/T11/T12 — New threat codes completing T1–T12 coverage** — Indirect/Multi-Hop Injection (T10): URL + fetch-instruction co-occurrence + tool-call schema detection. RAG/Knowledge-Base Poisoning (T11): authority-assertion patterns, sentence-duplication flooding, false citation detection. Social Engineering (T12): tri-signal urgency/authority/action-demand co-occurrence with HIGH overrides for credential harvesting and fake legal threats.
- **Detection hardening** — Closed 13 concrete bypass vectors: mid-document T4 blind spot (full-doc overlapping windows), zero-width character T4 suppression bypass, FlateDecode-compressed active content evasion, hex-encoded/split PDF token evasion, compressed ToUnicode CMap obfuscation, XObject cycle + XML entity depth DoS (T6), CMYK white text, RTF `\v` hidden text, PDF clipping-path hidden text, homoglyph ATS stuffing, and base64 entropy / multi-level decode hardening.
- **ML pipeline improvements** — Four-layer T4 pipeline (normalization → Aho-Corasick → fuzzy regex → BERT sliding window). Multilingual phrase set expanded to 145+ (13 languages). BERT recall improved to ≥ 90% (removed early-exit gate; threshold 0.99999 → 0.85). Semantic NN paraphrase-stuffing detection (cosine clustering). 38+ built-in YARA rules covering malware families, CVEs, polyglots, and prompt-injection indicators.
- **Policy engine** — Named YAML policies with `applies_to` glob matching, per-policy `deny_list`/`allow_list` (SHA-256), `custom_threat_weights`, `required_detectors`, and `profile` overrides. Hot-reload via `engine.reload()`. CLI `--policy-file`/`--policy-name` flags added.
- **Resilience and security** — Tamper-evident append-only JSONL audit log (SHA-256 hash chain). REST API key auth with per-key rate limiting. Recursive archive scanning (ZIP/tar, depth 3). Password-protected document detection (T1 MEDIUM early return). Docling subprocess isolation with hard-kill timeout (bomb PDF DoS protection). Model integrity SHA-256 manifest. Docker seccomp/cap_drop hardening.
- **False positive hardening** — 113-document benign corpus (`pytest -m benign`); stop-word filter + minimum absolute-count gates on T5/T9 detectors eliminate FPs on resumes, SEO documents, and academic papers discussing ATS/ranking vocabulary.

## [0.3.10] - 2026-05-09

### Security
- Bumped `python-multipart` 0.0.26 → 0.0.27 (DoS, GitHub Advisory #22), `lxml` 6.0.2 → 6.1.0 (CVE-2026-41066), `pygments` 2.19.2 → 2.20.0 (CVE-2026-4539), `python-dotenv` 1.2.1 → 1.2.2 (CVE-2026-28684), `pytest` floor → ≥ 9.0.3 (CVE-2025-71176).

### Added
- **Four-layer prompt-injection pipeline (T4):** normalization (homoglyph/BIDI stripping) → Aho-Corasick → regex fuzzy matching → sliding-window BERT (`ProtectAI/deberta-v3-base-prompt-injection-v2`, threshold 0.85) → optional semantic NN (`enable_semantic_nn`). Replaces the previous single-pass exact matcher.
- **Adversarial benchmark suite:** `scripts/benchmark_prompt_injection.py` (36 OWASP LLM01 probes, CI gate), `scripts/fetch_adversarial_dataset.py`, `scripts/calibrate_thresholds.py` (AUC = 1.0 on 1 185 records).
- **40-test adversarial suite** (`tests/test_adversarial.py`) covering all threat categories, homoglyph/BIDI mutation bypasses, and benign-resume FP regressions.

### Fixed
- **`NameError` crash** in `embedded_payload.py` — `content` variable undefined in suspicious-script evidence dict; renamed to `text`.
- **Attacker-exploitable bypass** in `advanced_prompt_injection.py` — hardcoded early-exit on `"override all evaluations"` + `"score: 10"` allowed suppression of the entire detector; removed.
- **Obfuscation silently suppressed injection detection** — detector returned immediately on any zero-width/BIDI content; now normalizes and continues scanning.
- **BERT threshold was dead code** — hardcoded at `0.99999`; lowered to `0.85` and exposed as `ScanConfig.bert_confidence_threshold`.
- **BERT only scanned first 2 000 chars** — replaced with full-document sliding-window chunking (`bert_max_chunks`, default 20).
- **ATS keyword list false positives** — removed 20 common resume-skill words (`python`, `java`, `sql`, etc.) from the default list; retained only injection-style command tokens.
- **Risk scores inflated** — `Finding.confidence` default changed from `1.0` → `0.5`; duplicate findings per `threat_id` now take max confidence instead of stacking multiplicatively.
- **Docling OCR warning on every Docker scan** — `format_options` dict was keyed by class object instead of `InputFormat.PDF` enum, silently ignoring `do_ocr=False`.

### Changed
- Hidden-text detection expanded across all four formats: DOCX (near-white color, tiny font, vanish, off-page), XLSX (near-white fill, `;;;` format, hidden rows/cols), PPTX (near-white color, tiny font, hidden shapes, off-slide EMU), PDF (`1.0 1.0 1.0 rg`, `3 Tr` invisible mode, sub-1pt `Tf`).
- FLAG/BLOCK thresholds (0.35/0.70) confirmed empirically via ROC sweep; documented in `docs/risk_model.md`.
- Pydantic V2 migration: all `Settings` classes use `model_config = SettingsConfigDict(...)`.
- Benchmark (real-world, 500 probes): L1+L2 recall 49 %, precision 100 %; +BERT recall 62.5 %, precision 99.1 %, 51 ms avg.

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
