---
title: Risk Scoring & Verdict Model — DocFirewall
description: How DocFirewall derives the scan verdict (ALLOW / FLAG / BLOCK) from finding classes, and the separately-computed risk score used for analytics and dashboards.
---

# Risk Scoring & Verdict Model

DocFirewall returns two outputs per scan:

- **`verdict`** — one of `ALLOW`, `FLAG`, `BLOCK`. Derived from the **classes** of the findings produced by the scan, not from a probabilistic score threshold.
- **`risk_score`** — a `float` in `[0.0, 1.0]` computed by probabilistic combination across non-INFO findings. Used for analytics, dashboards, and customer-facing severity bands. **Does not gate the verdict.**

This split is deliberate: a BLOCK decision should rest on definitive evidence (a YARA signature, an EICAR string, a `javascript:` URI, an embedded PE/ELF, etc.), not on accumulating multiple weak heuristic signals.

## Finding classes

Every [`Finding`](../api/python.md) carries a `verdict_class` field with one of three values:

| Class | What it means | Effect on verdict | Effect on risk score |
|---|---|---|---|
| `BLOCK` | **Definitive evidence of malicious intent** — YARA hit, EICAR test string, AV-engine-infected, policy deny-list match, `javascript:`/`data:`/`file:`/`vbscript:`/`jar:`/IP-literal URI in PDF or DOCX, CSV `=cmd\|...` DDE pipe, ODF `macro://` URI (CVE-2023-2255), RTF `\javascript` control word, JBIG2 + oversized dimensions (CVE-2021-30860), inline XLM + `veryHidden` sheet (Pikabot/IcedID dropper pattern), embedded PE/ELF/Mach-O/ISO-9660 (CVE-2023-36884), dropper-extension files inside a DOCX, `eval(atob(...))`/`powershell -enc`/`cmd.exe /c` in body text, `<script>`/`javascript:` in metadata, base64 decoded-to-dangerous content. | **Any single BLOCK-class finding → `verdict = BLOCK`.** Monotonic — no combination of REVIEW findings can BLOCK. | Contributes |
| `REVIEW` (default) | **Heuristic / suggestive signal** — most prompt-injection ML hits, indirect-injection co-occurrence patterns, PII presence, social-engineering tri-signal, ToUnicode CMap anomalies, ATS keyword-stuffing patterns, hidden text indicators. | Any REVIEW finding (and no BLOCK) → `verdict = FLAG`. Combinations no longer escalate to BLOCK. | Contributes |
| `INFO` | **Recorded for audit but not a verdict driver** — "PDF has N incremental update layers" (true of any edited PDF), descriptive structural patterns. | Never affects verdict. | Excluded from risk score entirely |

## Verdict derivation

```python
if any(f.verdict_class == VerdictClass.BLOCK for f in findings):
    verdict = Verdict.BLOCK
elif any(f.verdict_class == VerdictClass.REVIEW for f in findings):
    verdict = Verdict.FLAG
else:
    verdict = Verdict.ALLOW
```

That's the entire rule. `risk_score`, `config.thresholds.flag`, and `config.thresholds.block` do not appear in the verdict path.

## Risk score formula

The risk score is still computed for analytics and is exposed on `ScanReport.risk_score`:

$$ \text{risk} = 1 - \prod_{f \in \text{non-INFO findings}} \left(1 - w_{threat} \times w_{severity} \times \text{confidence}_f \right) $$

Severity weights:

| Severity | Weight |
|---|---|
| `CRITICAL` | 1.00 |
| `HIGH` | 0.80 |
| `MEDIUM` | 0.50 |
| `LOW` | 0.25 |
| `INFO` | (excluded) |

Threat weights (defaults — overridable via policy `custom_threat_weights`):

| Threat | Default weight |
|---|---|
| `T1_MALWARE` | 1.00 |
| `T2_ACTIVE_CONTENT`, `T6_DOS` | 0.90 |
| `T4_PROMPT_INJECTION`, `T10_INDIRECT_INJECTION`, `T11_RAG_POISONING` | 0.80 |
| `T12_SOCIAL_ENGINEERING` | 0.75 |
| `T7_EMBEDDED_PAYLOAD` | 0.70 |
| `T5_RANKING_MANIPULATION`, `T8_METADATA_INJECTION` | 0.60 |
| `T3_OBFUSCATION`, `T9_ATS_MANIPULATION` | 0.50 |

## Finding deduplication

Multiple detectors can fire on the same artifact (e.g. the same injection phrase detected by both fast-scan substring match and deep-scan Aho-Corasick). To prevent double-counting, findings are grouped by `(threat_id, evidence["malicious_text"][:80])` before aggregation; the **highest-confidence** finding per group survives. Without deduplication, two `p ≈ 0.5` findings on the same artifact would multiply to `≈ 0.75` and inflate the score.

## Deep-scan trigger

To save time on obviously-clean files, the **deep-scan stage** only runs when the fast-scan risk score is `≥ config.thresholds.deep_scan_trigger` (default `0.20`), or for any known Office/PDF/RTF/HTML format. Note: this `deep_scan_trigger` threshold is the *only* threshold that still gates control flow — it controls *whether* deep scanning runs, not the verdict.

## Why not just score thresholds?

Pre-0.4.4 the verdict was derived from `risk_score` crossing `thresholds.block` / `thresholds.flag`. That model produced false BLOCK verdicts on benign documents where several heuristic findings happened to combine: a resume with a `/AA` form field + a ToUnicode CMap pattern + PII could cross 0.70 with zero malicious content.

The class-based model fixes this: a BLOCK decision now points to a single, specific, explainable artifact that the reviewer can verify. FLAG queues still exist for the cases worth a human's attention, but the score is no longer mistaken for proof of malice.

See [`CHANGELOG.md`](../changelog.md) entry for 0.4.4 for the full migration notes.

## Plain-language explanations

Each Finding's `explain` field is intended for **non-technical reviewers**. The Scanner runs a post-process step (`detectors.explanations.enrich_findings`) that recognises the most common finding types and rewrites their `explain` text into plain prose — "this PDF is set up to run an action automatically the moment it's opened" rather than "Found suspicious token `/OpenAction` in raw file stream".

The original technical text is preserved verbatim in the new `Finding.technical_detail` field so SIEMs, forensic analysts, and rule engines that depend on stable string matching can keep working.

When `enrich_findings` does not recognise a finding type (because no entry has been added to the central mapping table yet), the finding passes through untouched — `explain` keeps the detector's original technical text, and `technical_detail` stays `None`. Coverage is intentionally rolled out incrementally for the most-encountered finding types first.

See `src/doc_firewall/detectors/explanations.py` for the mapping table and instructions on adding new entries.

## Backwards compatibility

- `ScanConfig.thresholds.flag` and `ScanConfig.thresholds.block` still exist on the config object; they no longer drive the verdict but are kept so downstream tools can use the values as customer-facing risk bands ("low / medium / high risk" labels on dashboards).
- `Policy.custom_threat_weights` continues to influence `risk_score` (still useful for tuning dashboards per corpus) but no longer changes verdict outcomes.
- The legacy `RiskModel.get_verdict(score)` call signature (without `findings`) still works but emits a `DeprecationWarning`.
- **`Finding.explain` is now plain-language** for recognised finding types. SIEM rules that key on the previous short technical strings should switch to `Finding.technical_detail` (which preserves the original verbatim) or to `Finding.title` / `Finding.module` / `Finding.evidence` for stable structured matching.
