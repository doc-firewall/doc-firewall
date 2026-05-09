---
title: Installation — Install DocFirewall via pip or Docker
description: Install DocFirewall with pip install doc-firewall. Requires Python 3.10+. Supports Docker and optional ClamAV integration for T1 malware scanning.
---

# Installation

DocFirewall can be installed via pip or used as a Docker container.

## Prerequisites

-   **Python 3.10+**
-   **ClamAV** (Optional, for local antivirus scanning)

## Standard Installation

To install DocFirewall locally, use pip.

```bash
# Install the package from PyPI
pip install doc-firewall
```

For Advanced Local ML Detection (Requires PyTorch/Transformers/Aho-Corasick):

```bash
pip install "doc-firewall[ml]"
```

!!! tip "Virtual Environments"
    It is highly recommended to use a virtual environment to avoid dependency conflicts.
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install doc-firewall
    ```

## External Dependencies

### ClamAV (Optional)
If you plan to use the local Antivirus feature, you need `clamscan` or `clamd` installed.

=== "Ubuntu / Debian"
    ```bash
    sudo apt-get update
    sudo apt-get install clamav clamav-daemon
    sudo freshclam
    ```

=== "macOS"
    ```bash
    brew install clamav
    ```

### Docling
DocFirewall uses [Docling](https://github.com/DS4SD/docling) for deep parsing. It installs its own dependencies (PyTorch, etc.). The installation process usually handles this automatically.

OCR is disabled by default — DocFirewall reads the text layer of PDFs directly. No OCR engine installation is required. If you see a `"No OCR engine found"` message in logs, it can be safely ignored; it has no effect on scan accuracy.

## Docker Support

For isolated environments, use the provided Docker image.

```bash
# Build the image
docker build -t doc-firewall .

# Run a test scan
docker run --rm -v $(pwd):/app doc-firewall scripts/validate_with_doc_firewall.py
```
