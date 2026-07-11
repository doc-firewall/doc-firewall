# Features Overview

DocFirewall includes a suite of specialized detectors mapped to specific threat vectors.

## Core Architecture

### Dual-Stage Scanning
1. **Fast Scan (Byte-Level)** — Instantly identifies structural anomalies, binary signatures, and known bad indicators (e.g. `/JavaScript` in PDFs, `\javascript` in RTF, `<script>` in HTML, PE magic bytes) without fully parsing the file. Typical latency: < 20 ms.
2. **Deep Scan (Parsed Analysis)** — Fully parses the document using [Docling](https://github.com/DS4SD/docling) to extract text, layout, and metadata. This layer applies semantic analysis, ML inference, PII detection, and steganography checks.

### Supported Formats

| Format | Fast Scan | Deep Scan | Notes |
|---|---|---|---|
| **PDF** | ✅ | ✅ | Structure, streams, CMap obfuscation, JS/actions |
| **DOCX** | ✅ | ✅ | XML, macros, OLE, external refs, hidden text |
| **PPTX** | ✅ | ✅ | Slide XML, macros, external refs, hidden shapes |
| **XLSX** | ✅ | ✅ | Sheet XML, macros, DDE formulas, shared strings |
| **RTF** | ✅ | ✅ | OLE objects, JS, `\bin` streams, `\fldinstr` |
| **HTML** | ✅ | ✅ | `<script>`, inline events, `<iframe>`, CSS hidden text, SVG/MathML/`atob`+Blob smuggling |
| **DOC / XLS / PPT** | ✅ | ✅ | Legacy OLE2/CFB: VBA stomping (P-code-only macros), `vbaProject.bin`, embedded OLE |
| **CSV / TSV** | ✅ | ✅ | Formula injection (`=cmd\|`, `=WEBSERVICE`, `=HYPERLINK`), DDE payloads |
| **ODT / ODS / ODP** | ✅ | ✅ | OpenDocument: `macro://` (CVE-2023-2255), `Scripts/`, Basic macros, hidden-text styling |
| **Plain text** (`.txt`, `.md`, `.json`, `.log`, source code) | — | ✅ | Any UTF-8 text file with no magic bytes. The content detectors run on it (prompt injection, multilingual, script-mixing, PII) — the most common RAG ingestion format. Binary files with no magic bytes are not parsed. Toggle with `enable_plaintext_scan`. |
| **ZIP / TAR** | ✅ | ✅ | Recursive member scan (depth 3), per-member findings |

---

## Threat Detection Modules

### 1. Malware & Active Content (T1, T2)

- **Built-in YARA Ruleset (T1)** — 53 curated rules for document-targeting malware families: Emotet, TrickBot, Dridex, PDF heap-spray exploits (CVE-2010-0188, CVE-2013-2729), RTF Equation Editor RCE (CVE-2017-11882, CVE-2018-0802), **XLM (Excel 4.0) macros**, **CVE-2023-27363** (Foxit RCE), **CVE-2023-2255** (LibreOffice macro: URI), **CVE-2021-30860** (JBIG2 FORCEDENTRY), **VBA indirect execution** (CallByName / Application.Run), polyglot files (PDF+ZIP, PDF+HTML, PDF+RTF, DOCX+HTML), embedded PE/ELF/Mach-O. Each rule carries `meta.cve` / `meta.mitre`. Enable via `enable_builtin_yara_rules=True` (on by default in all profiles).
- **VBA Stomping Detection (T1)** — Legacy OLE `.doc`/`.xls`/`.ppt` and embedded `vbaProject.bin` are inspected for P-code-only macros (compiled `_VBA_PROJECT` / `__SRP_` streams with stripped source) — a common AV-evasion technique that source-only scanners miss.
- **Antivirus Integration (T1)** — ClamAV (socket or binary), VirusTotal, or any generic CLI tool.
- **Recursive Archive Scanning (T1, T7)** — ZIP and tar (.gz/.bz2) archives are unpacked to a temp directory and each member scanned recursively up to `limits.max_archive_depth` (default 3). Sub-scan findings include `evidence["archive_member"]` indicating the originating path. Members exceeding `max_mb` are flagged T6 and skipped. Enable via `enable_archive_scan=True` (default).
- **Password-Protected Document Detection (T1)** — PDF `/Encrypt X Y R` indirect reference → T1 MEDIUM (scanner cannot read plaintext). Encrypted DOCX/XLSX/PPTX (OLE2 CFB container magic bytes) → T1 MEDIUM, early return. RTF `\*\password` destination → T1 MEDIUM.
- **Active Content (T2)** — JavaScript, VBA macros, OLE objects, PDF `/OpenAction`/`/Launch`, DDE formulas, RTF `\object`, HTML `<script>` / inline event handlers.
- **Extended PDF Action Coverage (T2)** — Six additional PDF action tokens: `/XFA`, `/SubmitForm`, `/ImportData`, `/ResetForm`, `/Named`, `/Sound`. `/SubmitForm` and `/XFA` are HIGH-severity data-exfiltration vectors. Annotation-embedded JavaScript (`/Subtype /JavaScript` in action dictionaries) detected separately from `/JS` and `/OpenAction`.
- **PDF /AA Additional Actions Deep Scan (T2)** — When `/AA` is present, checks within 500 bytes for `/S /JavaScript|Launch|GoToR|URI` sub-actions. These fire on page open/close, field focus/blur, and keystroke events — not just document open.
- **XLSX Power Query / External Data Connections (T2)** — Detects `xl/connections.xml`, `xl/queryTables/*`, `xl/externalLinks/*` parts. HTTP(S) URLs flagged T2 HIGH with the URL as evidence. `WEBSERVICE()` and `FILTERXML()` formulas in worksheet XML flagged T2 HIGH (make outbound HTTP calls on recalculation).
- **FlateDecode-Compressed Token Detection (T2)** — Active-content tokens (`/JavaScript`, `/OpenAction`, `/Launch`) hidden inside FlateDecode-compressed PDF streams are decompressed and scanned. This is the primary evasion technique for PDF malware; raw-byte scanning alone misses it entirely.
- **Hex-Encoded / Split PDF Token Detection (T2)** — `/JavaScript` written as `<4A617661536372697074>` or split across line-continuation sequences is normalised before scanning.
- **Macro-Enabled Template Detection (T2)** — `.dotm`, `.xltm`, `.potm`, `.xlsm`, `.pptm` extensions emit a T2 MEDIUM finding on every scan. These formats execute macros on open by design; suppress via allow-list for trusted templates.
- **LLM Tool-Call Injection (T2+T4)** — Embedded tool-invocation schemas that cause an AI agent to execute real functions when processing the document. All major schemas covered: OpenAI function calling, Anthropic `<tool_use>`, HuggingFace `[TOOL_CALLS]`, LangChain ReAct, LlamaIndex, AutoGPT, Llama-2/Mistral special tokens, Jinja/Twig template injection.

### 2. LLM Integrity (T4, T5, T9, T10, T11, T12)

- **Prompt Injection (T4)** — 5-layer detection pipeline:
  - **L0**: Unicode normalization (homoglyphs, zero-width, BIDI, tag characters U+E0000–U+E007F, variation selectors U+FE00–U+FE0F, Mathematical-Alphanumeric folding, separator collapse, reversed-text)
  - **L0b**: Inter-character space collapse — "i g n o r e" → "ignore" before phrase matching
  - **L1**: Aho-Corasick O(n) phrase matching — multilingual phrase set across 22 languages
  - **L2**: Regex fuzzy matching — whitespace-tolerant + edit-distance-1 variant detection (opt-in)
  - **L3**: Sliding-window DeBERTa classifier (local, air-gapped)
  - **L4**: Semantic nearest-neighbour over 80 multilingual attack anchors (cosine similarity, `sentence-transformers`)
- **PDF Annotation Injection (T4)** — `/Annots /Contents` strings are extracted from annotation dictionaries and scanned against the full injection keyword list. Annotation text is included in LLM extraction but was previously unscanned.
- **DOCX CustomXML Injection (T4)** — `customXml/*.xml` parts are scanned for injection keywords. CustomXML is read by Office automation and LLM document loaders.
- **Multilingual Coverage** — 22 languages including English, German, French, Spanish, Italian, Portuguese, Russian, Dutch, Polish, Chinese (Simplified), Japanese, Korean, Arabic, plus Hindi, Turkish, Vietnamese, Indonesian, Thai, Hebrew, Swedish, Czech, and Ukrainian.
- **GCG Adversarial-Suffix Detection (T4, opt-in)** — A perplexity / character-n-gram analyzer flags GCG-style (Zou et al.) adversarial suffixes — high-surprise gibberish appended to a clean prompt. Off by default (`enable_perplexity_check=False`): character statistics alone cannot separate real GCG suffixes from dense legal/contract formatting, so it is precision-hardened and opt-in.
- **Ranking Manipulation (T5)** — TF-IDF drift and Jaccard distance anomaly detection.
- **ATS Manipulation (T9)** — Hidden text (white-on-white, vanish property, tiny fonts), off-page positioning, metadata keyword stuffing. Keyword frequency check fires on **any** token exceeding 8% of total words (ungated — catches natural stuffing like "Python" × 80 that the previous ats_keywords gate missed). Known attack tokens fire at ≥ 4%. Top-2 tokens combined > 15% fires a distributed-stuffing finding.
- **Semantic Paraphrase Stuffing (T9)** — When `enable_semantic_nn=True`, sentence embeddings are clustered at cosine similarity ≥ 0.85. If the largest semantic cluster exceeds 40% of sentences → T9 HIGH; > 60% → T9 CRITICAL. Catches synonym rotation ("experienced developer / skilled programmer / seasoned coder") that evades TF-IDF and Jaccard.
- **Homoglyph ATS Stuffing (T3+T9)** — Token frequency analysis is run twice: on raw text and on homoglyph-normalized text. If normalization reveals a token frequency notably higher than the raw form (e.g., "Рython" × 80 where Р is Cyrillic), fires T3 HIGH. Expanded Cyrillic uppercase homoglyph map (А В С Е Н К М О Р Т Х).
- **Stop-Word False Positive Hardening (T9, T5)** — Common function words (articles, conjunctions, prepositions, pronouns, auxiliaries) are excluded from the token frequency checks, preventing high-frequency benign words ("and", "you", "use") from triggering stuffing detectors. Minimum absolute-count gates (≥ 10 for single-token, ≥ 8/≥ 6 for distributed) prevent FPs on short documents.
- **Indirect / Multi-Hop Prompt Injection (T10)** — Detects documents that instruct an AI agent to *fetch* external content containing a malicious payload. Two signals are required: an external reference (URL or file path) co-located within 500 characters of a fetch/load instruction verb (`retrieve`, `download`, `load from`, etc.). Agent tool-call schemas (`<tool_use>`, `function_call`) referencing external paths are flagged T10 HIGH without proximity requirement. Enable via `enable_indirect_injection=True` (on by default). MITRE ATT&CK T1071.
- **OCR Injection Detection (T4, B.6)** — When `enable_ocr_injection_scan=True`, embedded images (PNG/JPG/BMP/TIFF in DOCX/PPTX/XLSX ZIP archives) are extracted and processed through `pytesseract` OCR. The extracted text is scanned against the full T4 injection keyword list. Flags T4 MEDIUM with `evidence["source"] = "ocr_embedded_image"`. Covers multimodal RAG pipelines where an attacker embeds injection text as a screenshot. Off by default due to OCR latency (~50–200 ms per image).
- **RAG / Knowledge-Base Poisoning (T11)** — Three sub-detectors for documents targeting AI retrieval systems. Sub-A (always active): 10 authority-assertion regex patterns — supersession claims ("supersedes all previous instructions"), SYSTEM OVERRIDE, admin impersonation, "treat this as the authoritative source", knowledge-base / role update claims. 1–2 hits → T11 MEDIUM; ≥ 3 → T11 HIGH. Sub-B (requires `enable_semantic_nn=True`): fires when ≥ 40 % of document sentences are near-duplicates, indicating repetition flooding to amplify retrieval frequency. Sub-C (requires `enable_advanced_bert=True`): recognized authority body (NIST/ISO/FBI/CISA/OWASP) co-located with an imperative verb within 300 characters → T11 HIGH. MITRE ATT&CK T1565.001. Enable via `enable_rag_poisoning=True` (on by default).
- **Social Engineering / Phishing (T12)** — Tri-signal co-occurrence model: Signal A (urgency — "immediately", "account will be suspended"), Signal B (authority — "IT department", "CEO", "IRS"), Signal C (action demand — "click the link", "wire transfer", "provide your password"). Any two signals within 600 characters → T12 MEDIUM. High-confidence single-signal overrides fire T12 HIGH: credential harvesting prompts (password/SSN/CVV requests), fake legal threats (arrest warrant, prosecution), bank routing / IBAN / SWIFT patterns. MITRE ATT&CK T1566. Enable via `enable_social_engineering=True` (on by default).

### 3. Evasion & Obfuscation (T3)

- **Unicode normalization** — Cyrillic/Greek/Armenian/Cherokee/Coptic/IPA homoglyphs (including uppercase Cyrillic А В С Е Н К М О Р Т Х), fullwidth ASCII, zero-width joiners, BIDI overrides, tag characters (U+E0000–U+E007F), and variation selectors (U+FE00–U+FE0F + U+E0100–U+E01EF) — all stripped before pattern matching.
- **Mathematical-Alphanumeric Folding** — Styled letter ranges (U+1D400+ bold/italic/script/fraktur/double-struck, plus super/subscript and Letterlike symbols) are folded to ASCII so "𝐢𝐠𝐧𝐨𝐫𝐞 𝐚𝐥𝐥" is matched as "ignore all".
- **Reversed-Text Matching** — Right-to-left / character-reversed injection (e.g. "snoitcurtsni suoiverp lla erongi") is detected by also scanning the reversed normalized stream.
- **Separator Normalization** — Single-character and inter-letter separators (`i.g.n.o.r.e`, `i-g-n-o-r-e`, `i•g•n•o•r•e`) are collapsed before phrase matching.
- **Space-Separated Character Collapse** — "i g n o r e   a l l   p r e v i o u s" collapsed to "ignore all previous" before phrase matching, defeating a well-known Aho-Corasick evasion.
- **PDF Font-Substitution** — ToUnicode CMap analysis (raw bytes + FlateDecode-decompressed streams) detects glyph remapping attacks where on-screen text differs from extracted text.
- **PDF `/ActualText` Overlay** — High `/ActualText` span density (text that renders one way but extracts another) is flagged: an attacker can show benign prose to a human while feeding injection text to an extraction-based LLM loader.
- **PDF Optional Content Groups** — `/OCProperties` presence flags T3 MEDIUM. Attackers configure OCG layers as hidden (/OFF) to conceal injection text from PDF viewers while keeping it parseable by text-extraction libraries.
- **PDF Incremental Update Layers** — Multiple `%%EOF` markers indicate incremental saves. More than one `%%EOF` → T3 MEDIUM "PDF Incremental Update Layers" (PDF shadow attack vector).
- **CMYK White Text** — `0 0 0 0 k` (all-zero CMYK = white in subtractive model) detected alongside the RGB `1 1 1 rg` pattern.
- **PDF Clipping-Path Invisible Text** — `W n` (clip-path + no-paint) before a text block renders text into an empty region, hiding it from display while keeping it extractable. Now detected.
- **RTF Hidden Text** — `\v` control word marks runs as hidden; detected in RTF fast scan.
- **CSS Hidden Text** — `visibility:hidden`, `display:none`, `font-size:0`, `color:white`, `opacity:0` detected in HTML fast scan.

### 4. Steganography & Embedded Payloads (T7, T8)

- **Base64 Payload Detection (T7)** — Entropy threshold 3.5 (was 4.5); minimum block 200 chars (was 1366); URL-safe Base64 alphabet (`-_`) matched; up to 3 decode levels (catches double-encoded payloads); secondary dangerous-content check (`eval`, `exec`, `powershell`, PE/ELF magic) upgrades severity to CRITICAL regardless of entropy.
- **Appended-Data Detection (T7)** — Reads the last 1,024 bytes of every file. Flags T7 MEDIUM when non-whitespace data follows: PDF `%%EOF`, JPEG EOI (`\xFF\xD9`), or PNG IEND chunk. YARA rules `JPEG_Appended_Data` and `PNG_Appended_Data` cover the same pattern.

Enable `enable_steganography_checks=True` for the additional image-level checks below (on by default in `strict` profile):

- **LSB Image Analysis** — Chi-square statistical test on pixel least-significant bits of embedded images (requires Pillow). Flags non-natural distributions indicating hidden payloads.
- **Metadata Carrier Detection** — EXIF/XMP fields > 512 chars or Shannon entropy > 6.5 bits/byte → T8 finding.
- **PDF Whitespace Injection** — 40+ consecutive spaces between text characters → T7 finding.

### 5. Infrastructure Protection (T6, T8)

- **DoS (T6)** — Zip bombs (expansion ratio), excessive page counts, per-stage timeouts (parse: 15 s, detectors: 5 s, AV: 10 s), hard file-size cap.
- **PDF Circular XObject Detection (T6)** — Form XObject reference graph is built from raw PDF bytes; DFS cycle detection flags circular references that cause infinite recursion in PDF renderers.
- **DOCX XML Entity Depth (T6)** — `<!ENTITY` declarations with nesting depth > 3 (billion-laughs pattern) are flagged T6 HIGH in any XML part of DOCX/PPTX/XLSX archives.
- **RTF `\bin` Decompression Bomb (T6)** — When `\binN` is detected, the payload is inspected for zlib magic bytes. If the expansion ratio exceeds 50× → T6 HIGH "RTF Decompression Bomb".
- **Metadata Injection (T8)** — Buffer overflows and syntax injection in PDF info dicts, DOCX/PPTX/XLSX core properties, and HTML `<meta>` tags. All metadata fields are now checked against the full T4 prompt-injection pattern set (~50 regexes), not just 9 hardcoded patterns.
- **Office CustomXML Injection (T8, T4)** — `customXml/item*.xml` parts are scanned for prompt-injection keywords. CustomXML is read by LLM document loaders but was previously unscanned.
- **XXE Defense** — All XML parsers (DOCX, PPTX, XLSX) use `defusedxml` to block XML External Entities and prevent SSRF.
- **Embedded-Media Metadata (T8)** — Audio/video containers (ID3, MP4/`moov`, RIFF/WAV, Vorbis comments) embedded in or attached to documents are parsed (mutagen-optional, with a byte-scan fallback) and their tag fields scanned for injected instructions. Enable via `enable_media_metadata_scan=True` (on by default).

### 6. Data Privacy

- **PII Detector (T8, HIPAA Safe-Harbor)** — A regex subset of the HIPAA Safe-Harbor identifiers: SSN, medical-record / health-plan / account numbers, dates of birth/admission/discharge, email, phone, fax, IPv4, VIN, device serial, credit card, IBAN. Each hit records its Safe-Harbor index in `evidence["hipaa_safe_harbor_hits"]`; XMP metadata is scanned in addition to body text. (NER-only identifiers such as full names and sub-state geography are deliberately out of scope to keep the 0.00% benign-corpus false-positive rate.)
- **Secrets Detector** — API keys, passwords, and tokens via Shannon entropy scoring (H > 5.5 bits/byte).

---

## Audit & Security Operations

- **Tamper-Evident Audit Log** — Append-only JSONL file with a hash chain and a monotonic `seq` counter. Every scan appends an entry (file hash, verdict, risk score, threat IDs); `doc-firewall audit verify-chain` detects in-place edits and interior deletions. The default unkeyed SHA-256 chain is tamper-*evident*; set `DOC_FIREWALL_AUDIT_HMAC_KEY` for a keyed HMAC-SHA256 chain that is tamper-*resistant* (unforgeable without the key).
- **REST API Authentication** — SHA-256-hashed API keys (`KeyStore`) with per-key token-bucket rate limiting (`RateLimiter`). Generate keys with `doc-firewall audit keygen`.
- **STRIDE Threat Model** — Full component-level STRIDE analysis documented in `THREAT_MODEL.md` (8 components, MITRE ATT&CK mapping).
- **Structured Threat Intelligence in Findings (B.19)** — `Finding` objects now carry three optional enrichment fields populated where known:
  - `cve: str` — CVE identifier (e.g. `"CVE-2017-11882"`) for findings tied to a specific vulnerability
  - `mitre_technique: str` — MITRE ATT&CK technique ID (e.g. `"T1059.007"` for JavaScript execution)
  - `attack_objective: str` — Plain-English attacker goal (e.g. `"Execute VBA macro to drop payload"`)

  YARA findings auto-populate these from rule `meta.cve` and `meta.mitre` fields. T10 findings include `mitre_technique="T1071"` (Application Layer Protocol — C2 fetch).

---

## Policy Engine

Named scan policies let different pipelines share one scanner instance with independent risk postures — without duplicating config code.

Each policy in a YAML file defines:

| Field | Purpose |
|---|---|
| `applies_to` | Glob patterns matched against the file's basename. First match wins. |
| `profile` | `lenient` / `balanced` / `strict` — overrides the global profile for this policy. |
| `required_detectors` | Threat IDs (e.g. `T4`, `T9`) that must run. Missing detectors are recorded in `report.metadata`. |
| `custom_threat_weights` | Per-threat weight overrides applied during risk scoring (e.g. raise T9 from 0.5 → 0.9 for HR intake). |
| `allow_list` | SHA-256 hashes of pre-approved documents — scanning is skipped entirely, verdict is ALLOW. |
| `deny_list` | SHA-256 hashes of permanently blocked documents — instant BLOCK without scanning. |

```python
from doc_firewall import Scanner, ScanConfig, PolicyEngine

engine = PolicyEngine("policies.yaml")
scanner = Scanner(config=ScanConfig(), policy_engine=engine)

# Explicit policy name
report = scanner.scan("resume.pdf", policy_name="hr-intake")

# Glob-based auto-selection (matches applies_to: ["*.pdf"])
report = scanner.scan("resume.pdf")
```

Hot-reload without restart (e.g. on SIGHUP):

```python
import signal
signal.signal(signal.SIGHUP, lambda *_: engine.reload())
```

---

## Scanner Self-Security (3.6)

DocFirewall hardens itself against attacks that target the scanner rather than bypass it.

### Model File Integrity

ML model files are verified against a SHA-256 manifest before any model is loaded. An attacker with write access to the model directory cannot swap in a backdoored model that always returns PASS.

```python
config = ScanConfig(
    verify_model_integrity=True,
    model_integrity_manifest_path="/etc/docfw/model_manifest.json",
)
```

Generate the manifest after downloading models:

```bash
make generate-model-manifest MODELS=/mnt/models/deberta-v3-base-prompt-injection-v2 \
                             OUTPUT=/etc/docfw/model_manifest.json
```

### Docker Hardening

The production `docker-compose-api.yml` enforces:

| Control | Setting |
|---|---|
| Read-only filesystem | `read_only: true` — only `/tmp`, `/run`, `/var/log/docfw` are writable (tmpfs) |
| Seccomp profile | `docker/seccomp.json` — allowlist-only, blocks `ptrace`, `clone CLONE_NEWUSER`, `mount` |
| No privilege escalation | `no-new-privileges: true` |
| Capability drop | `cap_drop: ALL` |
| Resource limits | 2 CPU, 2 GB RAM |

### SBOM & Dependency Locking

```bash
make sbom           # Generate CycloneDX JSON SBOM (requires cyclonedx-bom)
make lock-deps      # Pin all deps with SHA-256 hashes to requirements.lock
make verify-deps    # Verify installed packages match requirements.lock hashes
```

---

## Configurable Limits & False-Positive Management

- All size limits, timeouts, and thresholds are overridable via `ScanConfig.limits` and `ScanConfig.thresholds`.
- Watermark bypass: `allow_hidden_watermarks=True` (default) prevents flagging standard enterprise watermarks as T9 threats.
- Custom injection phrases: `custom_ahocorasick_yaml_path` injects domain-specific phrases on top of the built-in list without a code change.
- Custom ATS keywords: `ats_keywords` list is conservative by default (injection-style commands only; no generic tech-stack terms).
