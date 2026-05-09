# Benchmarking

Performance is critical for high-throughput scanning. We provide tools to measure throughput (pages/sec) and accuracy (F1-score).

## Prompt Injection Accuracy Benchmark

A separate benchmark measures detection recall and precision on adversarial prompt-injection probes.

```bash
# Synthetic probes (36 probes, 7 OWASP LLM01 categories)
python scripts/benchmark_prompt_injection.py

# Real-world dataset (deepset/prompt-injections, 500 probes)
# Requires: python scripts/fetch_adversarial_dataset.py --limit 500
python scripts/benchmark_prompt_injection.py \
  --extra-probes dataset/ow1_prompt_injections.jsonl

# With BERT layer enabled (local model weights required)
python scripts/benchmark_prompt_injection.py \
  --extra-probes dataset/ow1_prompt_injections.jsonl \
  --bert --out dataset/benchmark_ow1_bert.jsonl
```

Baseline results (Layers 1+2, BERT off):

| Dataset | Recall | Precision | FPR | Latency |
|---|---|---|---|---|
| Synthetic (36 probes) | 100% | 100% | 0% | 0.04 ms |
| Real-world (500 probes) | 49% | 100% | 0% | 0.03 ms |
| Real-world + BERT | 63% | 99% | 0.3% | 51 ms |

The benchmark exits non-zero if overall recall on the synthetic suite drops below 90%, making it suitable as a CI gate.

## Running Benchmarks

DocFirewall includes a containerized benchmark environment to guarantee reproducibility across systems.

### Prerequisite

Make sure Docker is installed and running.

### Command

Use the `run_benchmark.sh` script to execute the full evaluation suite:

```bash
# This will:
# 1. Build the 'doc-firewall' docker image
# 2. Run validation against 410 T1-T9 test cases
# 3. Calculate precision/recall metrics
# 4. Generate a DOCX report
./run_benchmark.sh
```

The process takes approximately 45-60 minutes for the full dataset.

### Outputs

After completion, artifacts are available in:

-   **`dataset/scan_results.jsonl`**: Detailed per-file scan logs.
-   **`dataset/metrics_summary.json`**: Aggregated precision, recall, and F1 scores.
-   **`doc_guard_project/scripts/Scan_Report_YYYYMMDD.docx`**: Executive summary report.

## Metrics Calculation

We calculate metrics against the ground truth in `dataset/manifest.csv` (which covers 410 files).

### Definitions

The core metrics are defined as:

$$
Precision = \frac{TP}{TP + FP}
$$

$$
Recall = \frac{TP}{TP + FN}
$$

$$
F1 = 2 \cdot \frac{Precision \cdot Recall}{Precision + Recall}
$$

Where:
-   **TP (True Positive)**: Malicious doc correctly flagged.
-   **FP (False Positive)**: Benign doc flagged as malicious.
-   **FN (False Negative)**: Malicious doc missed.

## Profiling

To profile code hotspots:

```bash
python -m cProfile -o output.pstats scripts/run_scan.py
snakeviz output.pstats
```
