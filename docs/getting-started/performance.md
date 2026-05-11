---
title: Performance & Latency Targets
description: Documented P50/P95/P99 latency targets for DocFirewall by profile and format, plus tuning guidance.
---

# Performance & Latency Targets

DocFirewall uses a **dual-stage** scan architecture. Fast scan runs on raw bytes without full parsing
(sub-millisecond to ~20 ms). Deep scan runs structural analysis, ML detectors, and YARA rules
(latency depends on which detectors are enabled).

---

## Latency Targets by Profile

Targets were measured on a four-core CPU (no GPU) with synthetic representative documents.
Run `scripts/benchmark_throughput.py` to reproduce on your hardware.

| Profile | Target P95 | Detectors active |
|:---|:---|:---|
| `lenient` | **< 100 ms** | YARA + Aho-Corasick only |
| `balanced` *(default)* | **< 500 ms** | YARA + Aho-Corasick + all structural checks |
| `strict` | **< 2,000 ms** | Above + BERT classifier + steganography checks |
| `strict` + semantic NN | **< 3,000 ms** | Above + sentence-transformer cosine NN |

!!! note
    BERT (`enable_advanced_bert=True`) adds ~50 ms per document on CPU at the default
    `bert_max_chunks=20` setting. Reduce `bert_max_chunks` or run on GPU to lower this.

---

## P50 / P95 / P99 by Format (balanced profile, no ML)

| Format | P50 | P95 | P99 | Notes |
|:---|---:|---:|---:|:---|
| HTML | < 5 ms | < 15 ms | < 25 ms | Fastest — no ZIP overhead |
| RTF | < 8 ms | < 20 ms | < 35 ms | |
| XLSX | < 12 ms | < 40 ms | < 70 ms | ZIP + XML parse |
| PPTX | < 12 ms | < 40 ms | < 70 ms | |
| DOCX | < 15 ms | < 50 ms | < 90 ms | CustomXML + embeddings scan |
| PDF | < 20 ms | < 80 ms | < 150 ms | FlateDecode decompression adds variance |

Archive scanning (`enable_archive_scan=True`) adds latency proportional to the number and size
of archive members. A 50-member ZIP with DOCX files adds roughly 50 × single-file scan time.

---

## Throughput Estimates

| Profile | Target throughput | Notes |
|:---|:---|:---|
| `balanced` (heuristics only) | **≥ 20 docs/s** per CPU core | No ML loading overhead |
| `strict` (BERT, CPU) | **≥ 1–2 docs/s** per core | BERT inference dominates |
| `strict` (BERT, GPU) | **≥ 10–15 docs/s** | Batch inference (`bert_max_chunks` tuned up) |

---

## Tuning for Throughput

### Pre-compile at init time
All YARA rules and regex patterns are compiled once at `Scanner.__init__` — not per scan.
Instantiate one `Scanner` per process/thread and reuse it across all scans.

```python
scanner = Scanner(config=ScanConfig(profile="balanced"))
for path in document_queue:
    report = scanner.scan(path)   # reuses compiled rules and models
```

### Limit BERT chunks
```python
config = ScanConfig(
    enable_advanced_bert=True,
    bert_max_chunks=10,   # default 20 — lower = faster, misses mid-doc injections
)
```

### Reduce archive depth
```python
config = ScanConfig(
    enable_archive_scan=True,
    limits=Limits(max_archive_depth=1, max_archive_members=20),
)
```

### Disable OCR
`enable_ocr_injection_scan` is `False` by default. Leave it off unless your pipeline processes
documents from multimodal sources where injection text may be embedded in screenshots.

### Use strict profile selectively
Apply strict profile only to untrusted sources. Use balanced or lenient for documents from
known-good internal pipelines where throughput is critical.

```python
engine = PolicyEngine("policy.yaml")  # hr-intake → strict, internal → balanced
scanner = Scanner(config=ScanConfig(), policy_engine=engine)
```

---

## Running the Benchmark

```bash
# Default: 20 iterations × 6 formats × 2 profiles
python scripts/benchmark_throughput.py

# More iterations for stable P99 estimates
python scripts/benchmark_throughput.py --n 100 --output results.json

# Only benchmark the balanced profile (no ML model downloads needed)
python scripts/benchmark_throughput.py --profiles balanced
```

Sample output:

```
── Profile: balanced (n=20 iterations per format) ──
  ✅ html    P50=   3.2ms  P95=   8.1ms  P99=  11.4ms  287 docs/s
  ✅ rtf     P50=   6.8ms  P95=  17.3ms  P99=  24.6ms  135 docs/s
  ✅ xlsx    P50=  11.4ms  P95=  32.7ms  P99=  49.2ms   82 docs/s
  ✅ pptx    P50=  12.1ms  P95=  38.4ms  P99=  56.0ms   77 docs/s
  ✅ docx    P50=  14.3ms  P95=  47.2ms  P99=  71.8ms   65 docs/s
  ✅ pdf     P50=  18.9ms  P95=  62.5ms  P99= 104.3ms   49 docs/s
```

---

## Latency Breakdown (balanced profile, DOCX)

| Stage | Typical time | Driver |
|:---|:---|:---|
| Magic-byte detection | < 0.1 ms | File header read |
| Fast scan | 2–8 ms | Zip member iteration, regex |
| Deep parse (Docling) | 10–40 ms | XML parse + text extraction |
| Detectors (heuristics) | 3–15 ms | ATS, obfuscation, embedding checks |
| YARA (built-in ruleset) | 1–5 ms | Pre-compiled binary match |
| Audit log write | < 1 ms | Append-only JSONL |
| **Total (balanced)** | **~20–70 ms** | |
| BERT inference (strict) | +40–100 ms | DeBERTa v3, 20 windows |
| Semantic NN (strict+NN) | +15–30 ms | MiniLM-L6, cosine similarity |
