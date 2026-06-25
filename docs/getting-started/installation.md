---
title: Installation — Install DocFirewall via pip or Docker
description: Install DocFirewall with pip install doc-firewall. Requires Python 3.10+. Supports Docker, optional ClamAV for T1 malware scanning, and optional ML extras for advanced detection.
---

# Installation

DocFirewall can be installed via pip or deployed as a Docker container. Multiple installation profiles let you keep the deployment lightweight or pull in optional ML dependencies.

## Prerequisites

- **Python 3.10+**
- **ClamAV** (optional — for local antivirus scanning, T1)
- **Pillow** (optional — for steganography LSB analysis, T7)

## Installation Profiles

### Base install (heuristic + structural scanning only)

Fast startup, no ML dependencies. Covers all structural, YARA, regex, and heuristic detectors.

```bash
pip install doc-firewall
```

Typical scan latency: **< 20 ms** (fast scan), **< 100 ms** (deep scan without ML).

### Advanced ML detection

Adds PyTorch, Transformers, `sentence-transformers`, and `ahocorasick` for the full 5-layer prompt-injection pipeline, semantic nearest-neighbour, TF-IDF, and local BERT inference.

```bash
pip install "doc-firewall[ml]"
```

Required for `enable_advanced_bert`, `enable_semantic_nn`, `enable_advanced_ahocorasick`, and `enable_advanced_tfidf` config flags.

### Steganography LSB analysis (optional add-on)

Pillow is only needed for pixel-level LSB chi-square analysis (T7). If not installed, metadata entropy and PDF whitespace injection checks still run automatically.

```bash
pip install Pillow
```

!!! tip "Virtual environments"
    Always install into a virtual environment to avoid dependency conflicts.
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install "doc-firewall[ml]"
    ```

## External Dependencies

### ClamAV (optional — T1 malware)

Required only if `enable_antivirus=True` with `provider="clamav"`.

=== "Ubuntu / Debian"
    ```bash
    sudo apt-get update && sudo apt-get install clamav clamav-daemon
    sudo freshclam
    ```

=== "macOS"
    ```bash
    brew install clamav
    ```

### Docling (document deep parsing)

DocFirewall uses [Docling](https://github.com/DS4SD/docling) for full document parsing (text, layout, metadata extraction). It installs automatically as a dependency.

OCR is **disabled by default** — DocFirewall reads the native text layer of PDFs and Office files directly, which covers the vast majority of documents. OCR is only needed to read text that is *rendered inside an image* (a screenshot of text, text baked into a logo, or a QR code). See **Tesseract OCR** below.

### Tesseract OCR (optional — image-based injection & quishing)

Required only when you enable image inspection:

```python
config = ScanConfig(enable_ocr_injection_scan=True)   # OCR text inside images
config = ScanConfig(enable_qr_decode=True)            # decode QR / barcodes
```

`pip install "doc-firewall[ml]"` installs the Python wrapper **`pytesseract`** and **`Pillow`**, but it **cannot** install the Tesseract engine itself — Tesseract is a native (C++) binary, and PyPI packages cannot bundle OS executables. You must install it with your platform's package manager:

=== "macOS"
    ```bash
    brew install tesseract
    ```

=== "Ubuntu / Debian"
    ```bash
    sudo apt-get update && sudo apt-get install tesseract-ocr
    ```

=== "Fedora / RHEL"
    ```bash
    sudo dnf install tesseract
    ```

=== "Windows"
    ```powershell
    choco install tesseract
    # or download the installer from https://github.com/UB-Mannheim/tesseract/wiki
    # then ensure tesseract.exe is on your PATH
    ```

Verify the engine is visible:

```bash
tesseract --version
```

**What does NOT work if you skip the Tesseract binary:**

- **Image-based prompt injection is not inspected.** Instructions rendered inside an image (a screenshot of text, text in a banner/logo) are invisible to a text scanner. This is the exact vector the OCR layer exists to catch.
- **QR / barcode "quishing" detection (T10/T7) is inactive** even with `enable_qr_decode=True` — `pyzbar` also needs its native `zbar` library.
- **Image-only / scanned PDFs are flagged as an uninspected blind spot.** When `enable_ocr_injection_scan` is *off*, a document that is image-heavy with little extractable text raises a **T3 advisory** ("image-heavy document with little extractable text" → REVIEW) so a clean verdict is never silently assumed over un-inspectable content. Installing Tesseract **and** setting `enable_ocr_injection_scan=True` both inspects the images and auto-suppresses that advisory.

!!! warning "Do not set the flag without the binary"
    Setting `enable_ocr_injection_scan=True` while the Tesseract binary is missing will **suppress the blind-spot advisory without actually inspecting the images** — turning a visible "couldn't read this" warning into a silent gap. Install the binary first, or leave the flag off so the advisory keeps surfacing image-only documents for review.

If you have no need to read text inside images, it is safe to skip Tesseract entirely — every other detector (structural, JavaScript, metadata, the bundled ML injection classifier, multilingual layers) runs without it, and the coverage report will mark OCR as an inactive capability.

### YARA (built-in ruleset)

The `yara-python` package ships as a standard dependency and is required for the built-in 30+ rule malware ruleset (`enable_builtin_yara_rules=True`) and custom YARA rules (`yara_rules_path`).

## Local / Air-gapped Model Weights

When running in an air-gapped environment, pre-download the ML model weights and point `ScanConfig` at the local paths:

```python
from doc_firewall import ScanConfig

config = ScanConfig(
    enable_advanced_bert=True,
    bert_model_path="/mnt/models/deberta-v3-base-prompt-injection-v2",

    enable_semantic_nn=True,
    nn_model_name="/mnt/models/all-MiniLM-L6-v2",
)
```

Download once on a machine with internet access:

```bash
python -c "
from transformers import AutoTokenizer, AutoModelForSequenceClassification
AutoTokenizer.from_pretrained('ProtectAI/deberta-v3-base-prompt-injection-v2').save_pretrained('/mnt/models/deberta-v3-base-prompt-injection-v2')
AutoModelForSequenceClassification.from_pretrained('ProtectAI/deberta-v3-base-prompt-injection-v2').save_pretrained('/mnt/models/deberta-v3-base-prompt-injection-v2')

from sentence_transformers import SentenceTransformer
SentenceTransformer('all-MiniLM-L6-v2').save('/mnt/models/all-MiniLM-L6-v2')
"
```

## Docker Support

DocFirewall ships a pre-built Docker image with all dependencies (including ML extras) for isolated deployments.

```bash
# Standalone REST API microservice
docker-compose -f docker-compose-api.yml up -d

# Test a scan against the running service
curl -X POST -F "file=@suspicious.pdf" \
  "http://localhost:8000/scan?profile=strict&enable_ml=true"
```

Or run the scanner directly in a one-off container:

```bash
docker build -t doc-firewall .
docker run --rm -v $(pwd)/uploads:/uploads doc-firewall \
  doc-firewall scan /uploads/resume.pdf --json
```

## Contributing / Local Development

After cloning, activate the repo's pre-commit hooks once:

```bash
make install-hooks
```

This wires up `.githooks/pre-commit`, which blocks commits containing hardcoded local paths or scratch/debug filenames.
