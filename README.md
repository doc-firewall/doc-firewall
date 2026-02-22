# DocFirewall: Secure Document Intake for AI Pipelines

[![PyPI version](https://badge.fury.io/py/doc-firewall.svg)](https://badge.fury.io/py/doc-firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/doc-firewall/doc-firewall/badge)](https://securityscorecards.dev/viewer/?uri=github.com/doc-firewall/doc-firewall)

**DocFirewall** is a high-performance, configurable security scanner designed to protect Large Language Model (LLM) pipelines and document processing systems from malicious uploads. It performs static analysis and heuristic scanning on **PDF** and **DOCX** files to neutralize threats **before** they reach your parser or inference engine.

---

## 🛡️ Key Defenses

DocFirewall implements a multi-layered defense strategy covering the following threats:

| ID | Threat Vector | Description |
| :--- | :--- | :--- |
| **T1** | **Malware / Virus** | Integrates with Antivirus (ClamAV, VirusTotal) and Yara to detect known malware signatures. |
| **T2** | **Active Content** | Detects executable JavaScript, Macros (VBA), OLE objects, and PDF Actions. |
| **T3** | **Obfuscation** | Identifies homoglyphs, invisible text, and encryption used to bypass filters. |
| **T4** | **Prompt Injection** | Flags hidden instructions targeting LLM behavior (e.g., "Ignore previous instructions"). |
| **T5** | **Ranking Manipulation** | Detects keyword stuffing and statistical anomalies to artificially boost ranking. |
| **T6** | **Resource Exhaustion** | Prevents DoS attacks via Zip bombs, excessive page counts, and recursion. |
| **T7** | **Embedded Payloads** | Scans for embedded binaries (PE, ELF) and malicious object streams. |
| **T8** | **Metadata Injection** | Sanitizes metadata fields against buffer overflows and syntax injection. |
| **T9** | **ATS Manipulation** | Detects SEO poisoning and white-on-white text used to game ranking algorithms. |

---

## 🚀 Performance
DocFirewall employs a **dual-stage scanning architecture**:
1.  **Fast Scan**: 10ms-range byte-level analysis for known signatures and structural anomalies.
2.  **Deep Scan**: Full document parsing (powered by [Docling](https://github.com/DS4SD/docling)) for semantic analysis and complex vector detection.

**Benchmark Results:**
- **Precision**: 100%
- **Recall**: 100%
- **F1 Score**: 1.0
*(Validated on v3 Holdout Dataset containing 70+ adversarial samples)*

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/doc-firewall/doc-firewall.git
cd doc-firewall

# Install in editable mode
pip install -e .
```

## 📚 Documentation

Full documentation is available at [https://doc-firewall.readthedocs.io](https://doc-firewall.readthedocs.io) (example).

To build the documentation locally:

```bash
pip install mkdocs-material mkdocstrings[python]
mkdocs serve
```

---

## 💻 Usage

### Python API
The primary interface is the `scan()` function, which acts as a synchronous wrapper around the async core.

```python
from doc_firewall import scan, ScanConfig

# Default Configuration
report = scan("resume.pdf")

if report.verdict == "BLOCK":
    print(f"Blocked! Risk Score: {report.risk_score}")
    print("Findings:", report.findings)
else:
    print("Document is safe to process.")

# Custom Configuration
config = ScanConfig(
    enable_pdf=True,
    enable_docx=True,
    thresholds={"deep_scan_trigger": 0.4}
)
report = scan("contract.docx", config=config)
```

### Command Line Interface (CLI)
Quickly scan files from the terminal.

```bash
doc-firewall uploads/suspicious_file.pdf --json
```

### Docker Support
Run DocFirewall in an isolated container.

```bash
# Build the image
docker build -t doc-firewall .

# Run a scan (mounting local directory)
docker run --rm -v $(pwd):/app doc-firewall scripts/validate_with_doc_firewall.py
```

---

## 📊 Benchmarking & Reproducibility

DocFirewall includes a comprehensive benchmarking suite to generate datasets and validate performance.

```bash
# 1. Run the full benchmark pipeline (Dataset Gen -> Scan -> Metrics -> Report)
./run_benchmark.sh
```

This will produce:
- `metrics_summary.json`: Detailed F1/Precision/Recall stats.
- `evaluation_report.docx`: A Word document summarizing the security posture.
- `scan_results.jsonl`: Raw logs of every file scanned.

---

## 🔧 Configuration

You can tune DocFirewall via `ScanConfig`:

```python
class ScanConfig:
    profile: str = "balanced"  # paranoid, balanced, fast
    enable_pdf: bool = True
    enable_docx: bool = True
    ocr_enabled: bool = False  # Enable for image-based PDFs (slower)
    
    # Risk Thresholds (0.0 - 1.0)
    # Scores >= deep_scan_trigger will provoke parsing
    # Scores >= blocking_threshold will return verdict BLOCK
```

---

## 📜 License
MIT

