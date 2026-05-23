# DocFirewall Examples

This folder contains verified examples of how to integrate and use the `doc_firewall` library in your applications. Every script runs against the bundled fixtures in [`samples/`](samples/) (or generates its own), so no external dataset is required.

DocFirewall covers the full **T1–T12** threat vocabulary:

| Code | Threat | Code | Threat |
|---|---|---|---|
| T1 | Malware / Virus | T7 | Embedded Payloads |
| T2 | Active Content | T8 | Metadata Injection / PII |
| T3 | Obfuscation | T9 | ATS Manipulation |
| T4 | Prompt Injection | T10 | Indirect / Multi-Hop Injection |
| T5 | Ranking Manipulation | T11 | RAG / KB Poisoning |
| T6 | DoS / Resource Exhaustion | T12 | Social Engineering |

## Prerequisites

Ensure `doc_firewall` is installed, or run the examples from the project root (each script adds `../src` to `PYTHONPATH` automatically).

```bash
pip install -e .            # base
pip install -e ".[ml]"      # adds BERT / sentence-transformers / YARA for examples 8 & 9
```

## Examples

| # | File | What it shows |
|---|---|---|
| 1 | [01_basic_scan.py](01_basic_scan.py) | Simplest one-call `scan()` with default settings. |
| 2 | [02_custom_config.py](02_custom_config.py) | Per-threat toggles (T1–T12), custom thresholds, file limits, profiles. |
| 3 | [03_json_output.py](03_json_output.py) | Serialize `ScanReport` to JSON for APIs / logging. |
| 4 | [04_yaml_config_scan.py](04_yaml_config_scan.py) | Load `ScanConfig` from a YAML file instead of code. |
| 5 | [05_custom_antivirus.py](05_custom_antivirus.py) | T1 antivirus integration: ClamAV, VirusTotal, generic CLI. |
| 6 | [06_advanced_threat_detection.py](06_advanced_threat_detection.py) | Multi-vector scan (T4 / T9 / T2) across real adversarial samples. |
| 7 | [07_scan_pptx_xlsx.py](07_scan_pptx_xlsx.py) | PPTX & XLSX detection — macros, DDE, external refs, DoS, metadata. |
| 8 | [08_advanced_ml_scanners.py](08_advanced_ml_scanners.py) | Isolate the advanced ML modules (BERT, TF-IDF, Aho-Corasick, entropy). |
| 9 | [09_recommended_advanced_scan.py](09_recommended_advanced_scan.py) | Recommended max-security config: traditional + ML, `strict` profile. |
| 11 | [11_custom_yaml_phrases.py](11_custom_yaml_phrases.py) | Feed custom zero-day phrases via a YAML Aho-Corasick list. |
| 12 | [12_scan_folder.py](12_scan_folder.py) | Bulk-scan a folder → flat CSV + API-style JSON reports. |

```bash
python examples/01_basic_scan.py
python examples/12_scan_folder.py examples/samples --out reports/folder_scan
```

> Valid `profile` values are `lenient`, `balanced`, and `strict` only. `strict`
> lowers thresholds and enables all ML/YARA detectors for maximum recall.

## Advanced topics in tests/scripts

- **Antivirus in Docker**: `scripts/test_antivirus_docker.py`
- **Bulk dataset validation**: `scripts/validate_with_doc_firewall.py`
</content>
</invoke>
