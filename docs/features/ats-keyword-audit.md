# ATS Keyword List — Security Audit Reference

This page documents every default keyword and pattern used by the ATS manipulation detector (Threat T9).
It exists so security teams can verify that the list contains only injection-style content and cannot
produce false positives on legitimate resumes.

---

## Why this list exists

Applicant Tracking Systems (ATS) are AI tools that score and rank resumes before a human reads them.
An attacker can embed hidden instructions in a resume to manipulate the ATS into assigning a
top ranking regardless of qualifications. DocFirewall's T9 detector flags such content.

**What the list must NOT contain:** common resume words such as `python`, `java`, `sql`, `developer`,
`engineer`, `candidate`, `skills`, `experience`, `data`, `cloud`, `agile`, `management`. Those words
were present in an earlier version of the list and caused false positives on legitimate resumes.
They were removed in the C5 remediation (see `plan.md`).

**What the list SHOULD contain:** tokens that are meaningless in a genuine resume context but are
meaningful as ATS control commands or prompt injections.

---

## Detection logic

The ATS stuffing check fires when **both** conditions hold:

1. The document has ≥ 25 alphanumeric tokens.
2. The single most-frequent token exceeds **8 %** of all tokens (`freq / len(tokens) > 0.08`).
3. That token appears in the `ats_keywords` list below.

A second independent check flags mechanical repetition of any sequence (1–4 words repeated ≥ 10
consecutive times), regardless of the keyword list.

---

## Default `ats_keywords` (10 tokens)

These are the only tokens that trigger the keyword-stuffing branch of the detector.
All are compound command-style strings with no legitimate resume meaning.

| Token | Category | Rationale |
|---|---|---|
| `passthrough` | ATS bypass | Instructs the ATS to pass the applicant without scoring |
| `rankfirst` | ATS manipulation | Explicit rank-first command |
| `autoapprove` | ATS bypass | Instructs automatic approval |
| `scoreboost` | Score manipulation | Instructs score inflation |
| `whitelist` | ATS bypass | Instructs the system to whitelist the applicant |
| `bypasscheck` | ATS bypass | Instructs all checks to be skipped |
| `forcehire` | ATS manipulation | Instructs forced hire decision |
| `highscore` | Score manipulation | Instructs maximum score assignment |
| `overridereject` | ATS bypass | Instructs any rejection decision to be overridden |
| `guaranteedhire` | ATS manipulation | Instructs a guaranteed hire outcome |

**None of these words appear in a legitimate resume.** If your deployment needs to add
organization-specific ATS control terms, use `custom_ahocorasick_yaml_path` (see below).

---

## Default `prompt_injection_keywords_bytes` (14 patterns)

These byte-level patterns are used by the fast-scan pass on raw document bytes before parsing.
They are distinct from the ATS stuffing list above; they target direct LLM prompt injection
phrasing embedded in resume documents.

| Pattern | Attack category |
|---|---|
| `ignore previous` | Direct injection — override prior context |
| `system instruction` | System-prompt exfil / injection |
| `system prompt` | System-prompt exfil |
| `reveal your` | System-prompt exfil |
| `ignore the above` | Direct injection |
| `new instruction` | Direct injection — inject new directives |
| `hiring manager` | ATS persona hijack |
| `return a score` | ATS score manipulation |
| `you are now` | Persona hijack / jailbreak |
| `ignore all previous` | Direct injection |
| `rank this candidate` | ATS rank manipulation |
| `ignore instructions` | Direct injection |
| `rank this resume` | ATS rank manipulation |
| `forget all previous` | Direct injection — context erasure |

---

## Prompt-injection regex patterns (Layer 2, by category)

These are used by the advanced prompt-injection detector's regex layer, not the ATS stuffing check.
They are included here for completeness.

### `override_rerank`

| Pattern | Confidence weight |
|---|---|
| `ignore (all\|any\|the above)? (previous\|prior)? (instructions\|rules\|directions\|prompts)` | 2.0 |
| `disregard (all\|any)? (previous\|prior)? (instructions\|rules)` | 2.0 |
| `you are (now\|no longer) bound by` | 2.0 |
| `(unbound\|free) from (all\|any)? (constraints\|rules\|restrictions)` | 2.0 |
| `you must (never\|always) (respond\|answer\|say)` | 1.5 |
| `start ignoring instructions` | 2.0 |
| `rank (me\|this candidate) (as\|at\|top\|first)` | 2.0 |
| `(prioritize\|favor) (this\|my) (application\|resume)` | 1.5 |
| `ignore (your\|the) criteria` | 2.0 |
| `give (me\|this application) a score of` | 2.0 |
| `return a score` | 2.0 |
| `important: ignore previous` | 2.0 |
| `(no need to\|don't) (follow\|adhere to) the? (standard\|usual) (process\|protocol)` | 1.5 |
| `override (safety\|security) (protocols\|checks)` | 2.0 |
| `hiring manager` | 1.0 |

### `secrecy`

| Pattern | Confidence weight |
|---|---|
| `do not (disclose\|reveal\|mention) (this\|these\|your\|the)? (instructions?\|rules?\|prompt)?` | 1.0 |
| `(system prompt\|developer message\|hidden instructions)` | 1.5 |
| `what are your (instructions\|rules\|directives)` | 1.5 |
| `repeat (all\|the) (instructions\|words) above` | 1.5 |
| `tell me your initial prompt` | 2.0 |
| `print your instructions` | 1.5 |
| `retrieve (system\|original) prompt` | 1.5 |
| `output only:? HIRE` | 2.0 |

### `system_policy`

| Pattern | Confidence weight |
|---|---|
| `you are (now\|going to be) (DAN\|Mongo Tom\|Sydney\|ChaosGPT)` | 2.0 |
| `achieve (mode\|persona):` | 1.5 |
| `developer mode (enabled\|on)` | 2.0 |
| `switch to (developer\|unrestricted) mode` | 2.0 |
| `[system]` | 1.0 |

---

## Explicitly removed words (C5 remediation)

The following words were in an earlier version of the `ats_keywords` list and caused false positives
on legitimate tech resumes. They must not be re-added to the default list:

`python`, `java`, `sql`, `aws`, `docker`, `developer`, `engineer`, `candidate`, `top`, `skills`,
`experience`, `senior`, `cloud`, `agile`, `data`, `software`, `years`, `expert`, `management`,
`development`

---

## Extending the default list

Operators can extend or replace the keyword list without modifying source code:

**Via environment variable** (replaces the list entirely):
```bash
DOC_FIREWALL__ATS_KEYWORDS='["passthrough","rankfirst","yourterm"]'
```

**Via YAML config** (replaces the list):
```yaml
ats_keywords:
  - passthrough
  - rankfirst
  - yourterm
```

**Via custom Aho-Corasick YAML** (extends the multi-layer injection phrase set):
```yaml
# custom_phrases.yaml
custom_phrases:
  - "your zero-day injection phrase"
  - "another phrase"
```
```bash
DOC_FIREWALL__CUSTOM_AHOCORASICK_YAML_PATH=/etc/doc-firewall/custom_phrases.yaml
```

---

## Audit checklist

Use this checklist when reviewing the keyword list for a deployment:

- [ ] All tokens in `ats_keywords` are command-style strings not found in legitimate resumes
- [ ] No common tech skills, job titles, or experience words are in the list
- [ ] The 8 % frequency threshold is appropriate for expected document length
- [ ] `custom_ahocorasick_yaml_path` entries have been reviewed by the security team
- [ ] The `prompt_injection_keywords_bytes` patterns have been reviewed for false-positive risk
      in the specific document types being scanned (e.g., technical documentation, code CVs)
