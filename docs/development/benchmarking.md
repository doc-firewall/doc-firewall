# Benchmarking

Performance is critical for high-throughput scanning. We provide tools to measure throughput (pages/sec) and accuracy (F1-score).

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
