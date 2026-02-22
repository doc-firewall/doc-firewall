# Quick Start

Get up and running with DocFirewall in under 5 minutes.

## Prerequisites

-   Python 3.10+
-   (Optional) docker for running benchmarks
-   (Optional) clamav if T1 Malware scanning is required locally.

## 1. Minimal Example

The simplest way to scan a file is using the `scan()` wrapper.

```python title="scan_file.py"
from doc_firewall import scan

report = scan("resume.pdf")

print(f"Verdict: {report.verdict}") # ALLOW, FLAG, or BLOCK
print(f"Risk Score: {report.risk_score}")
```

## 2. Handling the Report

The `ScanReport` object contains a wealth of information about the scan.

```python
if report.verdict == "BLOCK":
    print("🚫 Security Alert!")
    for finding in report.findings:
        print(f"[{finding.threat_id}] {finding.title}")
        print(f"  Sev: {finding.severity}")
        print(f"  Explain: {finding.explain}")
        print(f"  Module: {finding.module}")
```

### Report Attributes

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `verdict` | `Verdict` | Final decision: `ALLOW`, `FLAG`, or `BLOCK`. |
| `risk_score` | `float` | Aggregate risk score (0.0 - 1.0). |
| `findings` | `List[Finding]` | List of individual security issues found. |
| `timings_ms` | `dict` | Execution time for each scan stage. |
| `content` | `dict` | (Optional) Extracted text/metadata if deep scan ran. |

## 3. Asynchronous Scanning

For high-throughput web servers (FastAPI/Django), use the `Scanner` class directly with `scan_async`.

```python
import asyncio
from doc_firewall import Scanner, ScanConfig

async def main():
    scanner = Scanner(ScanConfig(profile="fast"))
    
    # Non-blocking scan
    report = await scanner.scan_async("large_contract.pdf")
    print(report.verdict)

if __name__ == "__main__":
    asyncio.run(main())
```
