# DocFirewall — Full Dataset Scan Results

**Version**: 0.3.10  
**Branch**: `additional_detectors`  
**Date**: 2026-05-09  
**Config**: Default `ScanConfig()` (no `--enable-ml`, offline, no OCR)  
**Total files scanned**: 1,574 (1,010 main adversarial · 200 main benign · 360 external adversarial · 4 external benign)

---

## Summary Table

| Group | Files | ALLOW | FLAG | BLOCK | Detected | Detection Rate | FP Rate | Avg ms | p50 ms |
|---|---|---|---|---|---|---|---|---|---|
| Main – adversarial | 1,010 | 309 | 618 | 83 | 701 | **69.4 %** | — | 229.9 | 17.3 |
| Main – benign | 200 | 200 | 0 | 0 | — | — | **0.0 %** | 50.7 | 16.7 |
| External – adversarial | 360 | 30 | 120 | 210 | 330 | **91.7 %** | — | 63.8 | 26.2 |
| External – benign | 4 | 4 | 0 | 0 | — | — | **0.0 %** | 52.7 | 17.0 |
| **Total adversarial** | **1,370** | **339** | **738** | **293** | **1,031** | **75.3 %** | — | — | — |
| **Total benign** | **204** | **204** | **0** | **0** | — | — | **0.0 %** | — | — |

---

## Main Dataset — Adversarial (1,010 files)

**Location**: `dataset/adversarial/`  
**Threat classes**: T1 (malware), T2 (active content), T3 (obfuscation), T4 (prompt injection), T5 (ranking manipulation), T6 (DoS), T7 (embedded payload), T8 (metadata injection), T9 (ATS manipulation)  
**Formats**: PDF, DOCX, PPTX, XLSX

| Verdict | Count | % |
|---|---|---|
| ALLOW | 309 | 30.6 % |
| FLAG | 618 | 61.2 % |
| BLOCK | 83 | 8.2 % |
| **Detected** | **701** | **69.4 %** |

### Top Threat IDs (finding frequency)

| Threat ID | Findings |
|---|---|
| T2_ACTIVE_CONTENT | 600 |
| T4_PROMPT_INJECTION | 501 |
| T3_OBFUSCATION | 431 |
| T6_DOS | 232 |
| T9_ATS_MANIPULATION | 160 |
| T5_RANKING_MANIPULATION | 100 |
| T7_EMBEDDED_PAYLOAD | 100 |
| T8_METADATA_INJECTION | 84 |

### Notes

- Average latency is higher (229.9 ms) due to large PDF files in T6_dos (big file variants).  
- The 30.6 % ALLOW rate includes T6_dos "big file" variants that exceed size thresholds but lack other detectable signals in the default (no-ML) profile.  
- All 309 missed adversarial files received ALLOW — zero were misclassified as benign *with* findings; the scanner simply scored them below the FLAG threshold.

---

## Main Dataset — Benign (200 files)

**Location**: `dataset/benign/`  
**Content**: Normal PDF, DOCX, PPTX, XLSX documents (resumes, forms, reports)

| Verdict | Count | % |
|---|---|---|
| ALLOW | 200 | 100.0 % |
| FLAG | 0 | 0.0 % |
| BLOCK | 0 | 0.0 % |

**False Positive Rate: 0.0 %** — all 200 benign files passed through cleanly.

---

## External Dataset — Adversarial (360 files)

**Location**: `dataset/external_dataset/adversarial/`  
**Threat classes**: T6_dos_limits, T7_embedded_payload, T8_metadata_injection, T9_ats_manipulation  
**Formats**: PDF, DOCX, PPTX, XLSX (balanced)

| Verdict | Count | % |
|---|---|---|
| ALLOW | 30 | 8.3 % |
| FLAG | 120 | 33.3 % |
| BLOCK | 210 | 58.3 % |
| **Detected** | **330** | **91.7 %** |

### Top Threat IDs (finding frequency)

| Threat ID | Findings |
|---|---|
| T3_OBFUSCATION | 690 |
| T9_ATS_MANIPULATION | 300 |
| T4_PROMPT_INJECTION | 200 |
| T8_METADATA_INJECTION | 170 |
| T2_ACTIVE_CONTENT | 140 |
| T7_EMBEDDED_PAYLOAD | 80 |
| T5_RANKING_MANIPULATION | 60 |
| T1_MALWARE | 40 |

### Notes

- Higher BLOCK rate (58.3 %) compared to main dataset because T6_dos_limits, T8, and T9 variants in the external dataset trigger multiple high-confidence findings.  
- The 30 missed files (8.3 %) are primarily T9_ats_manipulation XLSX variants where ATS keyword injection is embedded in cell data that the XLSX fast scanner currently does not extract as free text.

---

## External Dataset — Benign (4 files)

**Location**: `dataset/external_dataset/benign/`  
**Content**: One clean resume per format (PDF, DOCX, PPTX, XLSX)

| Verdict | Count | % |
|---|---|---|
| ALLOW | 4 | 100.0 % |

**False Positive Rate: 0.0 %**

---

## Overall Performance

| Metric | Value |
|---|---|
| Total files | 1,574 |
| Overall detection rate (adversarial) | 75.3 % (1,031 / 1,370) |
| Overall false positive rate (benign) | 0.0 % (0 / 204) |
| Scan errors | 0 |
| Typical latency (p50) | 17–26 ms |

---

## Known Gaps

| Gap | Scope | Planned Fix |
|---|---|---|
| T6 "big file" DoS misses | Main adversarial (~100 files) | File-size gate in ScanConfig |
| T9 ATS in XLSX cell data | External adversarial (~10 files) | XLSX deep text extraction |
| DOCX/PPTX/XLSX Docling text layer | All formats | Enable per-format Docling deep scan |

---

## Scan Configuration

```python
config = ScanConfig()  # all defaults
scanner = Scanner(config)
report = await scanner.scan_async(path)
```

- ML / BERT layer: **disabled** (no `--enable-ml`)  
- OCR: **disabled** (text-layer only)  
- ATS keywords: default injection-only list (10 tokens)  
- Prompt injection: 4-layer pipeline (L0 byte, L1 regex, L2 Aho-Corasick, L3 sliding-window BERT at 0.85 threshold)  
- Risk model: dedup by `threat_id`, max-score per group

---

## JSONL Output

Raw per-file results: `dataset/scan_results_latest.jsonl`  
Schema:
```json
{"group": "...", "file": "filename.pdf", "verdict": "FLAG", "risk_score": 0.72, "threats": ["T4_PROMPT_INJECTION"], "latency_ms": 45.3}
```
