---
title: Policies — Named scan configurations per file type
description: DocFirewall's Policy Engine lets different pipelines share one scanner with independent risk postures, allow/deny lists, required detectors, and risk-score weighting. Bundled policies cover HR intake, legal review, and developer tools.
---

# Policies

A **policy** is a named bundle of scan configuration that can be applied to specific files (via glob match), or explicitly by name. One scanner instance can serve many pipelines with different postures — HR intake, legal review, internal-tools intake, etc. — without instantiating a separate `Scanner` per use case.

Policies are loaded from a YAML file via `PolicyEngine`:

```python
from doc_firewall import PolicyEngine, Scanner, ScanConfig

engine = PolicyEngine("/etc/docfw/policy.yaml")
scanner = Scanner(config=ScanConfig(), policy_engine=engine)

# Apply by name
report = scanner.scan("resume.pdf", policy_name="hr-intake")

# Or let glob matching pick by filename
report = scanner.scan("./uploads/some_contract.pdf")
```

Or via `ScanConfig`:

```python
config = ScanConfig(
    policy_path="/etc/docfw/policy.yaml",
    policy_name="hr-intake",   # default name when no glob matches
)
scanner = Scanner(config=config)
```

CLI flags mirror the API: `--policy-file PATH --policy-name NAME`.

## When does a policy still matter? (post-0.4.4)

Under the [class-based verdict model](risk-scoring.md), `custom_threat_weights` **no longer changes which files BLOCK** — verdicts are derived from finding classes. Policies remain useful for:

| Capability | Still does what? |
|---|---|
| `allow_list` (SHA-256 hashes) | Skips all scanning, returns `ALLOW` immediately. **Unchanged.** |
| `deny_list` (SHA-256 hashes) | Skips all scanning, returns `BLOCK` immediately. **Unchanged.** |
| `profile` (`lenient`/`balanced`/`strict`) | Sets ML feature flags + (now informational) score bands. **Unchanged.** |
| `required_detectors` | Records `report.metadata["missing_required_detectors"]` if a listed detector didn't run. Lets callers fail-closed when coverage is incomplete. **Unchanged.** |
| `custom_threat_weights` | Tunes `risk_score` (still shown on dashboards) but **does not change verdict** any more. |
| `applies_to` glob | First-match-wins routing rule (basename glob). |

The pre-0.4.4 reason for tuning `custom_threat_weights` was to avoid false BLOCKs on noisy-but-benign corpora (e.g. resumes triggering BLOCK from accumulated PII / format findings). That problem is now solved architecturally — the [verdict class](risk-scoring.md#finding-classes) of each finding controls the outcome, not the weighted sum. Custom weights are now a **dashboard / analytics knob**, not a safety knob.

## Bundled policies (`examples/policy.yaml`)

The shipped example file defines four named policies that cover the common deployment shapes. Copy them as-is or tailor them.

### `hr-intake` — Applicant Tracking System intake

Resume-shaped uploads (PDF / DOCX). Boosts `T9_ATS_MANIPULATION` and `T4_PROMPT_INJECTION` weights so those show up as high-band on dashboards. Includes example `allow_list` / `deny_list` entries.

```yaml
- name: hr-intake
  applies_to: ["*.pdf", "*.docx"]
  profile: strict
  required_detectors:
    - T4   # prompt injection must be checked
    - T9   # ATS manipulation must be checked
  custom_threat_weights:
    T9_ATS_MANIPULATION: 0.9
    T4_PROMPT_INJECTION: 0.9
  deny_list:
    - sha256: "0000…"
      comment: "Example: permanently blocked document"
  allow_list:
    - sha256: "1111…"
      comment: "Example: pre-approved template document"
```

### `legal-review` — Contract / agreement review

Strict scanning, T9 suppressed (legal docs aren't ATS targets), required coverage for T4 / T7 (embedded payloads) / T8 (metadata).

```yaml
- name: legal-review
  applies_to: ["*.pdf", "*.docx", "*.pptx"]
  profile: strict
  required_detectors:
    - T4
    - T7
    - T8
  custom_threat_weights:
    T9_ATS_MANIPULATION: 0.1
```

### `dev-tools` — Internal low-risk uploads

Lenient profile for trusted internal pipelines (config files, reports). T9 entirely disabled.

```yaml
- name: dev-tools
  applies_to: ["*.xlsx", "*.html", "*.rtf"]
  profile: lenient
  custom_threat_weights:
    T9_ATS_MANIPULATION: 0.0
```

### `default` — wildcard fallback

Catches anything not matched by a more specific glob. Plain `balanced` profile, no overrides.

```yaml
- name: default
  applies_to: ["*"]
  profile: balanced
```

## Schema reference

```yaml
policies:
  - name: my-policy           # required, must be unique within the file
    applies_to:               # list of basename globs (fnmatch); ["*"] = all
      - "*.pdf"
      - "*.docx"
    profile: balanced         # lenient | balanced | strict
    required_detectors:       # threat-IDs that must fire OR be recorded as missing
      - T4
      - T9
    custom_threat_weights:    # per-threat float overrides (0.0–1.0) — affects risk_score only
      T9_ATS_MANIPULATION: 0.9
      T4_PROMPT_INJECTION: 0.8
    allow_list:               # SHA-256s that skip scanning → instant ALLOW
      - sha256: "abc…"
        comment: "Pre-approved template"
    deny_list:                # SHA-256s that skip scanning → instant BLOCK
      - sha256: "def…"
        comment: "Known-malicious document"
```

**Resolution order** (`PolicyEngine.get_for_file`):

1. If the caller passes `policy_name=` explicitly, that named policy wins (no glob check).
2. Otherwise, walk the policy list **in declaration order**; the first policy whose `applies_to` globs match the file's basename wins.
3. If nothing matches and a `policy_name` was set in `ScanConfig`, that becomes the fallback.
4. Otherwise, no policy is applied (default `ScanConfig` behavior).

## When to write a custom policy

Strong signal that you need one:
- You have **known-good hashes** (templates, prior-approved files) you want to ALLOW without re-scanning every upload.
- You have **known-bad hashes** (previously detected malicious files) you want to BLOCK without re-scanning.
- You need to **require specific detectors** to fire and fail closed if they don't (e.g. T4 prompt-injection must run for an LLM-facing pipeline).
- Different upload paths share one Scanner but need different `profile` settings.

Weaker signal (still valid, but less load-bearing now):
- You want to tune dashboard risk-band labels per corpus (the `custom_threat_weights` use case).

Less reason to write one anymore:
- You're trying to avoid false BLOCKs on a benign corpus. **Not needed.** The verdict-class model handles this without per-corpus tuning. If you're seeing unexpected BLOCKs, file a bug — every BLOCK now traces to a definitive BLOCK-class finding.

## Hot reload

`PolicyEngine.reload()` is thread-safe and can be called from a SIGHUP handler. Existing in-flight scans on other threads continue with the snapshot they captured; new scans see the reloaded set.

```python
import signal

def _on_sighup(_signum, _frame):
    engine.reload()

signal.signal(signal.SIGHUP, _on_sighup)
```

See also: [Risk Scoring & Verdict Model](risk-scoring.md), [Configuration](../getting-started/configuration.md#policy-engine).
