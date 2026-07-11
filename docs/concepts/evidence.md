# The Evidence Contract

*New in 0.4.8.*

A scanner verdict you can't verify is a verdict you can't automate. Since
0.4.8, doc-firewall enforces a hard contract on every finding that can
drive a decision:

> **Every finding with severity `HIGH`/`CRITICAL` or
> `verdict_class == BLOCK` carries one of:**
>
> 1. **`evidence["malicious_text"]`** — the actual offending content: the
>    injected prompt, the text hidden in a 0-size font, the resolved
>    `/OpenAction` JavaScript body, the launch command, the suspicious URI.
> 2. **`evidence["evidence_unavailable_reason"]`** — why the content could
>    not be extracted (encrypted stream, unsupported filter, compressed
>    object region), **plus `evidence["debug_steps"]`** — concrete commands
>    you can run to dig the content out of the document yourself
>    (`pdf-parser.py -o 12 -f file.pdf`, `olevba file.doc`,
>    `unzip -p file.docx word/document.xml`, …).

This means you can safely automate on it:

```python
report = scanner.scan("incoming.pdf")
if report.verdict == Verdict.BLOCK:
    for f in report.findings:
        if f.verdict_class == VerdictClass.BLOCK:
            print(f.title)
            print("  evidence:", f.evidence.get("malicious_text")
                  or f.evidence.get("evidence_unavailable_reason"))
            for step in f.evidence.get("debug_steps", []):
                print("  debug:", step)
```

## What 0.4.8 changed under the hood

**PDF actions are resolved, not just counted.** Before 0.4.8 an
`/OpenAction` token produced `{"token": "/OpenAction", "count": 2}` at
HIGH severity — the reviewer couldn't see what the action did. The scanner
now follows the object reference and classifies the target:

| Resolved action | Result |
|---|---|
| `/S /JavaScript` | script body extracted into `malicious_text` |
| `/S /URI` | target URL extracted; scheme-tiered |
| `/S /Launch` | command line extracted; HIGH |
| `/S /GoTo` / bare destination | **benign** — "open at page N" is standard in exported PDFs; reported as INFO, never flags the document |
| `/S /Named` | viewer command extracted; `NextPage`-class actions are benign |
| unresolvable (encrypted / unsupported filter) | `evidence_unavailable_reason` + `debug_steps` |

`/AA` (additional actions) and `/Next` action chains get the same
treatment.

**Hidden text findings carry the hidden text.** DOCX gained this in 0.4.6;
0.4.8 adds parity for PPTX (the run following the invisible styling) and
ODF (the `styles.xml` hidden style is joined to the `content.xml` spans
that use it). XLSX white-cell styling still reports `contract-only`
evidence (the style→cell→sharedStrings join is not implemented); the
finding explains that and tells you which part to dump.

**Snippets are centered on the match.** Evidence used to be the first 250
characters of the field — often containing none of the matched content.
Every regex-based finding now centers `malicious_text` on the match and
includes the exact `match` text separately.

**One configurable length cap.** `malicious_text` is truncated to a single
authoritative maximum — `ScanConfig.evidence_max_chars` (**default 250**) —
applied uniformly to every finding by the evidence contract, so SIEM output is
bounded and consistent across detectors. Truncated values end with `…`. Raise
the cap for richer context or lower it to shrink log volume.

**Misleading labels were renamed.** "SQL Injection in Metadata"
(HIGH, confidence 0.9) is now "SQL-like Syntax in Metadata" (MEDIUM, 0.6):
it is a heuristic that needs either two distinct SQL tokens or statement
punctuation to fire at all, and the evidence shows the actual SQL.

**Incomplete scans are never silent.** If a scan stage exceeds its budget
(10 minutes per stage by default, doubled in 0.4.8), the report gains a
`scan_timeout` finding that escalates the verdict to at least FLAG —
`on_timeout_verdict="block"` fails closed. The finding states explicitly
that this is an operational signal, not a malice claim, and its
`debug_steps` show how to re-run with a bigger budget.

## Coverage transparency — know what's actually running


Several of the strongest detectors are **opt-in** and depend on optional
packages: YARA and an antivirus engine (T1 malware signatures), and
sentence-transformers / BERT / OCR / perplexity (the ML layers of T4 prompt
injection). With a default `pip install doc-firewall` and the default
config they are **off**, so the scanner runs on baseline regex/structural
checks only — and previously it did so *silently*.

Now every report tells you what was active:

```python
report = scanner.scan("incoming.pdf")
print(report.coverage["degraded"])          # True in reduced-coverage mode
print(report.coverage["degraded_threats"])  # e.g. ["T1", "T4"]
print(report.coverage["threat_status"])     # {"T1": "baseline-only", ...}
print(report.coverage["profile"])           # effective profile that actually ran (0.5.1)
print(report.coverage["effective_config"])  # {"profile":…, "fast_only":…, "ml":{…}}
```

The `profile` / `effective_config` keys *(0.5.1)* let a caller confirm what
actually ran — not just what they think they configured — closing the gap where
a mis-set profile could silently degrade detection.

A Scanner built in reduced-coverage mode also logs one loud warning naming
each inactive capability and exactly how to turn it on.

To **fail closed** when promised detection is inactive:

```python
cfg = ScanConfig(profile="strict")
cfg.require_full_coverage = True            # any T1/T4 with no active detector → >= FLAG
# or require specific capabilities:
cfg.required_capabilities = ["yara", "semantic_nn"]
```

A document scanned with a required capability missing can no longer return
ALLOW — it carries a `reduced_coverage` finding and escalates to FLAG.

## Stable evidence schema (for SIEM consumers)

*Stabilised in 0.5.1.* The `evidence` dict is open-ended — detectors add
threat-specific keys — but the following keys are **stable** and safe to build
SIEM queries, dashboards, and alerting on. New releases may add keys; these will
not be renamed or repurposed without a major-version bump.

| Key | Type | Meaning | When present |
|---|---|---|---|
| `malicious_text` | string | The offending content (or a match-centred excerpt), capped at `evidence_max_chars` (default 250; truncated values end with `…`). | Every HIGH/CRITICAL/BLOCK finding whose content is extractable. |
| `malicious_text_source` | string | The original evidence key the `malicious_text` was promoted from (e.g. `hidden_text`, `match`, `target`). | When the value was promoted by the evidence contract. |
| `subtype` | string | Detector-specific refinement of the T-code (e.g. `csv_dde`, `reduced_coverage`, `decompression_budget`). | Detector-dependent. |
| `evidence_unavailable_reason` | string | Why the content could not be extracted (encrypted, unsupported filter, binary region). | Only when `malicious_text` is absent on a decision-driving finding. |
| `debug_steps` | list[string] | Concrete, copy-pasteable commands to extract the content manually. | Alongside `evidence_unavailable_reason`. |
| `archive_member` | string | Path of the originating member inside a scanned ZIP/tar. | Findings raised on an archive member. |

Each finding also carries these **stable top-level** fields (see
`Finding.to_dict()`): `threat_id`, `severity`, `title`, `explain`, `confidence`,
`module`, `verdict_class`, and — when set — `mitre_technique`, `cve`,
`attack_objective`. The `malicious_text` cap is configurable via
`ScanConfig.evidence_max_chars` and applied uniformly across all detectors.

Note: a format-*parsing* enabler (e.g. `olefile`, which lets the scanner
read legacy `.doc`/`.xls`/`.ppt`) is **not** counted as malware
*detection* — T1 still reports `baseline-only` unless YARA or an AV engine
is active.

## Content the scanner can't read

Encrypted PDFs (`/Encrypt`) and password-protected Office files are a
potential blind spot.

**Encrypted PDFs are decrypted and scanned where possible (0.5.0).** Many
"encrypted" PDFs use *permissions-only* encryption with an **empty user
password** ("you can open this but not print/edit"). With the optional
`[crypto]` extra (`pip install doc-firewall[crypto]`, pikepdf), the scanner
decrypts these transparently — **no password needed** — and scans the full
content; the prior blind-spot finding is downgraded to INFO. Real
password-protected PDFs are decrypted only if the password is supplied via
`ScanConfig.pdf_passwords`. Controlled by `enable_pdf_decryption` (default
on; a graceful no-op without pikepdf).

**What can't be decrypted** (no password, or `[crypto]` not installed, or
password-protected Office) falls to `on_unscannable_verdict`:

| value | behaviour |
|---|---|
| `warn` (default) | FLAG, with a `debug_steps` recipe (`qpdf --decrypt`, `msoffcrypto-tool`) |
| `block` | fail closed — un-inspectable content is BLOCKed |
| `allow` | recorded as INFO only |

## Guarantee

`make benchmark` measures contract compliance across the adversarial
corpus on every release; `scripts/benchmark_gate.py` fails the release if
compliance is below 100 %.
