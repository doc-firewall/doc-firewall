# DocFirewall — STRIDE Threat Model

**Version**: 0.4.x  
**Date**: 2026-05-09  
**Scope**: `doc-firewall` Python library and its CLI entry point. Deployment infrastructure (web servers, container runtimes, identity providers) is out of scope — the integrating developer owns those layers.

---

## Architecture Overview

```
Untrusted Document
        │
        ▼
┌───────────────────┐
│   Scanner.scan()  │  ← Public API entry point
│   (scanner.py)    │
└────────┬──────────┘
         │
         ├──► Stage 1: Fast Scan (byte-level, format-specific)
         │         pdf/fast_scan, docx/fast_scan, …
         │
         ├──► Stage 2: Parsing (format to ParsedDocument)
         │         pdf/parser, docx/parser, rtf/parser, html/parser …
         │
         ├──► Stage 2b: Format Checks (active content, obfuscation)
         │         detect_pdf_active_content, detect_pdf_obfuscation, …
         │
         ├──► Stage 2c: Detectors (text-level, ML-optional)
         │         PromptInjectionDetector, YaraDetector,
         │         AdvancedPromptInjectionDetector (BERT, NN),
         │         SteganographyDetector, MetadataInjectionDetector, …
         │
         └──► RiskModel → ScanReport (verdict, score, findings)
                  └──► AuditLog (optional immutable JSONL chain)
```

Trust boundary: **everything outside** `Scanner.scan()` is untrusted input.

---

## STRIDE Analysis Per Component

### 1. `Scanner` / Entry Point (`scanner.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S** — Spoofing | Attacker passes a symlink that resolves to a sensitive file | `os.path.isfile` + `os.path.realpath` check; symlink targets that do not exist are rejected |
| **T** — Tampering | Attacker replaces the file between hash computation and scanning | SHA-256 is computed before scanning begins; findings reference the hash, not the live file |
| **R** — Repudiation | No audit trail of scan decisions | Append-only SHA-256-chained JSONL audit log (`AuditLog`); `verify_chain()` detects any tampering |
| **I** — Information Disclosure | `ScanReport.content` leaks document text beyond the 250-char evidence snippet | `content["text"]` is truncated to 1 000 chars; evidence fields are capped at 250 chars per finding |
| **D** — DoS | Zip-bomb or massive file stalls scanner indefinitely | Hard file-size limit (`max_mb`); per-stage timeouts via `asyncio.wait_for`; parsing timeout 15 s; detectors timeout 5 s |
| **E** — Elevation of Privilege | Scanner runs arbitrary code embedded in a document | No `eval`, no `exec`, no subprocess during scanning; all ML inference is sandboxed in a ThreadPoolExecutor |

### 2. Fast Scan Layer (`analyzers/*/fast_scan.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S** | Magic-byte forgery (`.docx` file with PDF magic bytes) | Extension/magic-byte mismatch detection; trust magic bytes over extension |
| **T** | Attacker mutates the file mid-scan via hard link | File is opened once and read into memory up to `fast_pdf_token_scan_mb` limit; no re-read |
| **I** | Byte patterns expose scanner detection logic via error messages | All error details go to `structlog` only; public API returns opaque `ScanReport` |
| **D** | Pathological regex / huge token count exhausts CPU | Regex patterns avoid catastrophic backtracking (no nested quantifiers); scan limited to first 2 MB |
| **E** | OLE/DDE trigger during parsing | Fast scan operates on raw bytes only; no format library instantiation at this stage |

### 3. Parsing Layer (`analyzers/*/parser.py`, `utils/docling_convert.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S** | Polyglot document parsed by multiple parsers → inconsistent finding set | Magic-byte check unifies type; parser is chosen deterministically by `ftype` |
| **T** | XML entity injection (Billion Laughs, XXE) in DOCX/PPTX/XLSX | All XML parsed via `defusedxml`; external entity resolution disabled |
| **T** | Zip bomb in OOXML container | Total uncompressed size checked before extracting any part; per-part size limit enforced |
| **I** | Docling writes document content to its own cache | `DOCLING_DISABLE_OCR=1` prevents OCR model download; scanner never writes extracted text to disk |
| **D** | Deeply nested ZIP (recursive ZIP-in-ZIP) | Only the top-level ZIP is extracted; no recursive archive support in the parser |
| **D** | Maliciously crafted XLSX with millions of shared string references | `sharedStrings.xml` size capped at 16 MB; max sheet count from config |
| **E** | `striprtf` / `html5lib` optional deps have their own attack surface | Both are opt-in; if not installed, conservative fallbacks are used that process only plain text |

### 4. Detector Layer (`detectors/`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S** | Attacker crafts document that mimics a benign signature | Multi-layer detection (byte → regex → ML); each layer is independent |
| **T** | Adversarial text that causes BERT to misclassify | DeBERTa model is loaded from a verified local path; model integrity check planned (Phase 3.6) |
| **I** | ML model output contains sensitive training data | All models are local; no data leaves the machine; model output is a classification label + score only |
| **D** | Aho-Corasick automaton OOM on huge phrase list | Automaton is built once and cached; phrase list is finite and version-pinned |
| **D** | YARA scan of a large binary stalls scanner | YARA is optional; binary scan timeout inherited from detectors stage (5 s default) |
| **E** | YARA rule file controlled by an attacker to cause arbitrary file reads | `yara_rules_path` is a config value; production deployments should restrict write access to the rules directory |

### 5. Risk Model (`risk_model.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **T** | Attacker crafts findings that numerically drive risk score below the BLOCK threshold | Risk model uses a product-of-complements formula; adding more findings never decreases score; score is always in [0, 1] |
| **T** | Threat weight table tampered at runtime | `RiskModel` reads weights from `ScanConfig` at construction time; config is validated by Pydantic |
| **D** | Degenerate finding list (e.g. 10 000 findings) causes O(n) scoring to block | Finding count is naturally bounded by the per-document detector pipeline; no feedback loop |

### 6. Audit Log (`audit_log.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **T** — Tampering | Attacker edits a past JSONL entry to change a BLOCK verdict to ALLOW | SHA-256 hash chain: each entry includes `prev_hash` and `entry_hash`; `verify_chain()` detects any edit |
| **T** | Attacker appends a forged entry | A forged entry would break the chain because it cannot reproduce the previous legitimate hash without the full history |
| **R** | Entries deleted from the middle | Deletion breaks the chain; `verify_chain()` reports the first broken link |
| **I** | Audit log exposes document content | Audit entries contain only `file_sha256`, `verdict`, `risk_score`, `threat_ids`; no text content or evidence snippets |
| **D** | Disk exhaustion via large audit log | Log growth is proportional to scan volume; log rotation/retention is the deployer's responsibility |
| **E** | Log path is writable by untrusted process | Log file permissions are set by the OS; deployers must restrict write access to the audit log directory |

### 7. REST API Layer (`api.py`, `api_auth.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S** — Spoofing | Unauthenticated client poses as trusted service | SHA-256-hashed API key validated by `KeyStore`; keys never stored in plaintext |
| **T** | MIME type spoofing to bypass extension checks | Content-Type validated against allowlist; extension also checked; magic bytes checked during scan |
| **D** | Request flood exhausts server resources | Per-key token-bucket rate limiter (`RateLimiter`); `Content-Length` hard cap enforced before parsing body |
| **I** | Error messages leak internal details (stack traces, paths) | All exceptions return only a trace ID; details are sent to `structlog` only |
| **E** | Uploaded file path traversal | Scanner calls `os.path.abspath` + `os.path.realpath`; non-regular files are rejected |

### 8. CLI (`cli/main.py`)

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **T** | User pipes untrusted path to `doc-firewall scan` | Scanner validates path existence and regular-file status before processing |
| **I** | `--output` writes report to attacker-controlled path | Output path is specified by the authenticated CLI user; no privilege escalation is involved |
| **D** | `rules test` on a malicious YARA file causes `yara-python` to fault | YARA compile errors are caught and reported; scanner process is not affected |

---

## Data Flow — Trust Levels

```
[Untrusted] Document bytes
      │
      │  validated: size, magic bytes, symlink check
      ▼
[Semi-trusted] ParsedDocument (structured, no raw bytes after parsing)
      │
      │  analyzed by deterministic + ML detectors
      ▼
[Trusted] ScanReport (findings, score, verdict)
      │
      │  written to:
      ├──► stdout / JSON (caller's responsibility)
      └──► AuditLog JSONL (no document content, only hash + verdict)
```

**Invariant**: Document text is never written to disk by the library. The caller receives `ScanReport.content["text"]` (1 000-char truncated) and `Finding.evidence["malicious_text"]` (250-char truncated) in-memory only.

---

## Residual Risks (Accepted / Planned Mitigations)

| Risk | Acceptance Rationale | Planned Mitigation |
|------|---------------------|-------------------|
| ML model weights are not integrity-checked at startup | Models are loaded from a local path specified by the operator; tamper risk is low in a controlled deployment | Phase 3.6: SHA-256 manifest check at startup |
| `yara-python` links native code; a YARA bug could crash the process | YARA is opt-in; disabled by default | Subprocess isolation for YARA in a future release |
| `ParsedDocument` lives in-memory; OOM on adversarial large files | File size cap + per-stage timeouts limit worst-case memory | Phase 3.6: process isolation for ML detectors |
| Thread pool shares a process with the caller; a detector crash kills the caller | Detectors wrapped in `try/except`; failures produce a conservative finding | Phase 2.3: multiprocessing circuit breaker per detector |

---

## MITRE ATT&CK Mapping

| Technique | DocFirewall Detector |
|-----------|---------------------|
| T1566.001 — Spearphishing Attachment | YARA (Emotet/Trickbot/Dridex rules), EmbeddedPayloadDetector |
| T1059.007 — JS / PDF exploit | fast_scan_pdf (JavaScript token), YARA (PDF_JS_Obfuscated_Eval) |
| T1204.002 — Malicious File Execution | detect_pdf_active_content (/OpenAction /Launch), YaraDetector |
| T1203 — Client-Side Exploitation | YARA (PDF shellcode, CVE rules) |
| T1137.001 — Office Macro | detect_docx_macros, YARA (Office_VBA_AutoExec) |
| T1559.002 — DDE | YARA (Office_DDE_Execution) |
| T1027 — Obfuscated Files | TextObfuscationDetector, detect_pdf_obfuscation (CMap analysis), SteganographyDetector |
| T1027.002 — Software Packing | YARA (Polyglot_PDF_ZIP, Embedded_PE) |
| T1221 — Template Injection | YARA (Office_Template_Injection) |
| T1600 — Prompt Injection (LLM) | PromptInjectionDetector, AdvancedPromptInjectionDetector, InjectionNNDetector |
| T1598 — ATS Manipulation | ATSManipulationDetector, AdvancedATSNLPDetector |
