---
title: Quick Start — Scan Your First Document in 5 Minutes
description: Scan a PDF or DOCX for prompt injection and malware with DocFirewall in minutes. Includes sync and async API examples, ScanReport attributes, and YAML configuration.
---

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

print(f"Verdict: {report.verdict.name}") # ALLOW, FLAG, or BLOCK
print(f"Risk Score: {report.risk_score}")
```

## 2. Handling the Report

The `ScanReport` object contains a wealth of information about the scan.

```python
if report.verdict == "BLOCK":
    print("🚫 Security Alert!")
    for finding in report.findings:
        print(f"[{finding.threat_id.name}] {finding.title}")
        print(f"  Sev: {finding.severity.name}")
        # `explain` is the plain-language summary (suitable for non-tech reviewers).
        print(f"  What this means: {finding.explain}")
        # `technical_detail` is the under-the-hood context (populated by the
        # plain-language enricher for recognised finding types; None otherwise).
        if finding.technical_detail:
            print(f"  Under the hood : {finding.technical_detail}")
        print(f"  Module: {finding.module}")
        if "malicious_text" in finding.evidence:
            print(f"  Malicious Text: {finding.evidence['malicious_text']}")
```

### Report Attributes

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `verdict` | `Verdict` | Final decision: `ALLOW`, `FLAG`, or `BLOCK`. **Derived from finding classes** (see below), not from `risk_score` thresholds. |
| `risk_score` | `float` | Aggregate risk score (0.0 - 1.0). Computed for analytics / dashboards; does not gate the verdict. |
| `findings` | `List[Finding]` | List of individual security issues found. Each carries `verdict_class` (`BLOCK` / `REVIEW` / `INFO`). |
| `timings_ms` | `dict` | Execution time for each scan stage. |
| `content` | `dict` | (Optional) Extracted text/metadata if deep scan ran. |

!!! info "How `verdict` is determined (0.4.4+)"
    - Any finding with `verdict_class = BLOCK` (YARA hit, EICAR, `javascript:` URI, embedded executable, etc.) → `BLOCK`.
    - Otherwise, any finding with `verdict_class = REVIEW` (the default — heuristic / suggestive signals) → `FLAG`.
    - Otherwise (no findings, or only `INFO`-class) → `ALLOW`.

    See [Risk Scoring & Verdict Model](../concepts/risk-scoring.md) for the full taxonomy.

### Finding fields

Each `Finding` in `report.findings` carries:

| Field | Type | Description |
| :--- | :--- | :--- |
| `threat_id` | `ThreatID` | One of T1–T12 (see [Threat Model](../concepts/threats.md)). |
| `severity` | `Severity` | `INFO` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`. |
| `confidence` | `float` | 0.0 – 1.0; detector's self-assessed certainty. |
| `verdict_class` | `VerdictClass` | `BLOCK` / `REVIEW` / `INFO` — what kind of decision this finding can drive. |
| `title` | `str` | Short label (e.g. `"Suspicious PDF Token found: /OpenAction"`). |
| `explain` | `str` | **Plain-language summary** intended for non-technical reviewers. For recognised finding types, rewritten by the explanation enricher into "what this means" prose. |
| `technical_detail` | `Optional[str]` | **Under-the-hood detail** (PDF dictionary keys, CVE references, attack-chain context). `None` for finding types not yet covered by the enricher — their `explain` stays technical and `technical_detail` is `None`. |
| `evidence` | `Dict[str, Any]` | Per-detector structured payload. Common keys: `malicious_text`, `snippet`, `context`, `token`, `subtype`. |
| `module` | `Optional[str]` | The detector module that emitted the finding (useful for filtering / debugging). |
| `cve` | `Optional[str]` | CVE identifier when the finding ties to a known vulnerability. |
| `mitre_technique` | `Optional[str]` | MITRE ATT&CK technique ID (e.g. `"T1566"`). |

!!! tip "SIEM integrations"
    If you parse finding text in a SIEM or log shipper, switch from `explain` to `technical_detail` for recognised finding types — `explain` is now optimised for human reviewers and may contain multiple sentences of plain prose. The detector's original short technical text is preserved verbatim in `technical_detail`.

## 3. Asynchronous Scanning

For high-throughput web servers (FastAPI/Django), use the `Scanner` class directly with `scan_async`.

```python
import asyncio
from doc_firewall import Scanner, ScanConfig

async def main():
    scanner = Scanner(ScanConfig(profile="balanced"))
    
    # Non-blocking scan
    report = await scanner.scan_async("large_contract.pdf")
    print(report.verdict)

if __name__ == "__main__":
    asyncio.run(main())
```
