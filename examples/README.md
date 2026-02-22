# DocFirewall Examples

This folder contains verified examples of how to integrate and use the `doc_firewall` library in your applications.

## Prerequisites
Ensure `doc_firewall` is installed or the `src` folder is in your `PYTHONPATH`.

```bash
pip install -e .
```

## Examples

### 1. [Basic Usage](01_basic_scan.py)
The simplest way to scan a file using default settings.
```bash
python examples/01_basic_scan.py
```

### 2. [Custom Configuration](02_custom_config.py)
How to configure specific checks, change sensitivity thresholds, and enforce file limits.
```bash
python examples/02_custom_config.py
```

### 3. [JSON Output / API Integration](03_json_output.py)
How to serialize the `ScanReport` to JSON, suitable for logging or returning responses in a REST API.
```bash
python examples/03_json_output.py
```

## Advanced Topics available in tests/scripts
- **Antivirus Integration**: See `scripts/test_antivirus_docker.py`.
- **Bulk Scanning**: See `scripts/validate_with_doc_firewall.py`.
