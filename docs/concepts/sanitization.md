# Sanitization — safe copies for RAG ingestion

*New in 0.5.0.*

Detection answers *"is this dangerous?"*. For an LLM/RAG ingestion pipeline
the more useful question is often *"give me a safe version I can ingest."*
`Scanner.sanitize()` produces a **cleaned copy** of a document — hidden text
removed, dangerous metadata emptied, active content stripped, located
injections neutralised — while preserving the visible content, plus an
auditable record of everything it removed.

```python
from doc_firewall import Scanner

scanner = Scanner()
result = scanner.sanitize("incoming_resume.docx")

if result.sanitized:
    for r in result.removed:
        print("removed:", r.kind, "—", r.detail, r.excerpt or "")
    ingest(result.output_path)      # safe to feed your RAG/LLM pipeline
    import os; os.remove(result.output_path)   # caller owns the temp copy
else:
    block(result.reason)            # no safe copy could be produced
```

## What gets removed, per format

| Format | Removed |
|---|---|
| **DOCX / PPTX / XLSX** | hidden runs (vanish, white-on-white, ≤2pt font, off-page); VBA macro parts (`vbaProject.bin`); injection-bearing metadata (keywords/description/subject/custom props) |
| **PDF** *(needs `[crypto]`)* | document & page `/OpenAction`/`/AA`, the JavaScript name tree, annotation actions, AcroForm `/XFA`, embedded files, `/Info` + XMP metadata |
| **CSV / TSV** | formula-injection neutralised — cells starting with `= + - @` get a leading apostrophe so a spreadsheet treats them as text |
| **HTML** | `<script>` blocks, inline `on*` event handlers, `javascript:` URLs, hiding styles (`display:none`, `font-size:0`, …) |

Formats without a sanitizer return `sanitized=False` with a `reason`, so a
caller can fall back to BLOCK.

## Configuration

Sanitization is **opt-in by call** (nothing is sanitized unless you call
`sanitize()`) and **non-destructive** (the original file is never modified).
Three controls:

```python
cfg = ScanConfig()
cfg.enable_sanitization = False          # master off-switch → sanitize() returns sanitized=False
cfg.sanitize_remove_categories = [       # restrict what's stripped (default: all)
    "hidden_text", "macro",              # e.g. strip these but KEEP metadata
]
result = Scanner(cfg).sanitize("doc.docx", output_path="cleaned.docx")  # choose destination
```

Categories: `hidden_text`, `metadata`, `macro`, `active_content`,
`embedded_file`, `formula_injection`. `output_path` defaults to a temp file
the caller owns.

## Guarantees & limits

- **Visible content is preserved** — only invisible / unsafe constructs are
  removed. A sanitized résumé keeps the candidate's real text.
- **The result re-scans clean** — by design, feeding `output_path` back into
  `scan()` returns ALLOW (covered by the round-trip test).
- **It is conservative**, not a full document rebuild: it targets the
  constructs the detectors flag. For maximum assurance, re-scan the
  sanitized copy before ingesting (one line, and it should be ALLOW).
- **PDF sanitization requires `pikepdf`** (`pip install doc-firewall[crypto]`);
  without it PDFs return `sanitized=False` (fall back to BLOCK). pikepdf also
  decrypts permissions-encrypted PDFs in passing.
