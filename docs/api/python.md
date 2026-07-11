# Python API Reference

## Usage patterns

**Construct once, reuse.** A `Scanner` compiles automata and loads the bundled
ML classifier at construction; build one per process and reuse it. The
module-level `scan()` / `scan_bytes()` helpers reuse a cached default `Scanner`
for the default-config path, so the common one-liner is already fast.

```python
from doc_firewall import Scanner, scan, scan_bytes

scanner = Scanner()                       # reuse across many documents
report = scanner.scan("resume.pdf")       # scan a path
report = scanner.scan_bytes(blob, filename="resume.pdf")   # scan in-memory bytes
report = scanner.scan_stream(upload.file, filename=upload.filename)  # scan a file-like
```

**In-memory / stream scanning (0.5.1).** RAG and web-upload pipelines usually
hold the document in memory. `scan_bytes(data, filename=...)` and
`scan_stream(fileobj, filename=...)` accept the bytes directly — the library
spools to a private temp file, scans, and cleans up, so you don't manage temp
files yourself. `filename` supplies the extension for type detection and is
reported back as `report.file_path`; the internal temp path is never exposed.
Content-hash result caching still applies.

**Thread-safety (0.5.1).** A single `Scanner` is safe to share across threads
and `asyncio` tasks:

- Detectors are constructed and prepared once in `__init__`; per-scan work uses
  only local state, and scans do not mutate shared detector state.
- `scan()` runs on an internal `ThreadPoolExecutor` and is re-entrant; calling it
  from inside a running event loop is handled (it offloads to a worker).
- The optional result cache and the audit log are internally locked.

Reuse one `Scanner` across your worker pool rather than one per request. The one
caveat: treat a returned `ScanReport` as owned by the caller — mutating
`report.findings` is fine (cache hits return a copied list), but don't share a
single report object across threads and mutate it concurrently.

## `scan`

::: doc_firewall.scan
    handler: python
    options:
      show_root_heading: true
      show_source: true

## `scan_bytes`

::: doc_firewall.scan_bytes
    handler: python
    options:
      show_root_heading: true
      show_source: true

## `Scanner`

::: doc_firewall.Scanner
    handler: python
    options:
      show_root_heading: true
      show_source: true

## `ScanConfig`

::: doc_firewall.ScanConfig
    handler: python
    options:
      show_root_heading: true
      show_source: true

## `ScanReport`

::: doc_firewall.report.ScanReport
    handler: python
    options:
      show_root_heading: true
      show_source: false

## `Finding`

::: doc_firewall.report.Finding
    handler: python
    options:
      show_root_heading: true
      show_source: false

## `PolicyEngine`

::: doc_firewall.PolicyEngine
    handler: python
    options:
      show_root_heading: true
      show_source: false

## `Policy`

::: doc_firewall.Policy
    handler: python
    options:
      show_root_heading: true
      show_source: false

## `ModelIntegrityChecker`

::: doc_firewall.security.ModelIntegrityChecker
    handler: python
    options:
      show_root_heading: true
      show_source: false
