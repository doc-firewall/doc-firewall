# CLI Reference

DocFirewall provides a command-line interface for ad-hoc scanning.

## `doc-firewall`

```bash
doc-firewall [OPTIONS] FILE_PATH
```

### Arguments

-   `FILE_PATH`: Path to the file to scan.

### Options

-   `--json`: Output results in JSON format (default: human readable text).
-   `--config PATH`: Path to a `doc_firewall_config.yaml` file.
-   `--profile [balanced|strict|lenient]`: Override the scan profile.
-   `--debug`: Enable verbose logging.

### Examples

**Scan a file and print summary:**
```bash
doc-firewall resume.pdf
```

**Scan and output JSON for a pipeline:**
```bash
doc-firewall suspicious.docx --json > results.json
```
