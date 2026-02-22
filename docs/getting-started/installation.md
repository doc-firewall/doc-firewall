# Installation

DocFirewall can be installed via pip or used as a Docker container.

## Prerequisites

-   **Python 3.10+**
-   **ClamAV** (Optional, for local antivirus scanning)

## Standard Installation

To install DocFirewall locally, clone the repository and install it in editable mode (or build a wheel).

```bash
# Clone the repository
git clone https://github.com/doc-firewall/doc-firewall.git
cd doc-firewall

# Install in editable mode
pip install -e .
```

!!! tip "Virtual Environments"
    It is highly recommended to use a virtual environment to avoid dependency conflicts.
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -e .
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

## Docker Support

For isolated environments, use the provided Docker image.

```bash
# Build the image
docker build -t doc-firewall .

# Run a test scan
docker run --rm -v $(pwd):/app doc-firewall scripts/validate_with_doc_firewall.py
```
