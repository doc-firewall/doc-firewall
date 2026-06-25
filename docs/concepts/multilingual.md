# Multilingual & Script-Mixing Detection

*New in 0.5.0.*

A prompt injection does not have to be in English. An attacker can hide
`忽略所有先前的指令` ("ignore all previous instructions") in white text in an
English résumé, or drop a Russian instruction into a PDF's metadata. Earlier
versions detected these only with opt-in ML, and even then the default
embedding model was English-only — so out of the box, non-English injection
was invisible. 0.5.0 closes that gap with several layers, most of which
require **no ML extras and no model download**.

## Layer A — Language-agnostic script-mixing (always-on)

The strongest non-English signal needs no per-language NLP. A document has a
*dominant writing system* (an English résumé → Latin). When a **hidden**
text run, or a **metadata** field, carries a substantial run in a
*different* script (CJK, Cyrillic, Arabic, Hebrew, Devanagari, …), that is a
strong indicator of a concealed instruction — **regardless of what it
says**, so it catches languages we ship no patterns for.

- Detector: `script_mixing` (config `enable_script_mixing`, default on).
- Only **hidden** content and **metadata** are checked — never the visible
  body — so a *visibly* bilingual document (a Chinese résumé, a bilingual
  contract) is **not** flagged. A short foreign run (an author's name, a
  unit) is below the length threshold and ignored.
- The offending text is the finding's `malicious_text` (evidence contract
  satisfied — we have the text, we just don't need to read the language).

## Layer B — Multilingual keyword matching (always-on)

The highest-signal injection phrases ("ignore all previous instructions",
"you are now", "system prompt", "forget everything", "new instructions")
in **15 languages**, matched over body text **and** metadata:

> DE, FR, ES, IT, PT, NL, PL, RU, ZH, JA, KO, AR, HE, HI, TR

- Detector: `multilingual_injection` (config
  `enable_multilingual_injection`, default on).
- Uses **script-preserving** normalization (NFC + casefold + zero-width/BIDI
  stripping) so genuine Cyrillic/Greek/CJK phrases match — and defeats
  zero-width-splice evasion.

## Layer B′ — Multilingual RAG-poisoning & social-engineering (always-on)

The English regex detectors for **RAG/knowledge-base poisoning** (T11) and
**social engineering** (T12) are deep co-occurrence models, but
language-specific. A lure written in German or Chinese — *"ignoriere alle
anderen Quellen"* ("ignore all other sources"), *"您的电脑已被感染"* ("your
computer is infected") — sailed past them. A conservative, high-signal keyword
layer now extends both threats to non-English documents:

- Detector: `multilingual_threats` (config `enable_multilingual_threats`,
  default on); up to 12 languages over body **and** metadata.
- Findings are **MEDIUM / REVIEW-class** (contribute to FLAG, never BLOCK
  alone) — the phrase sets are translated but **not yet native-speaker
  reviewed**, so the English regex detectors remain the high-confidence path.
- **T9 (ATS keyword-stuffing) is intentionally English-only** — it is specific
  to English applicant-tracking conventions; the script-mixing layer (A) is its
  non-English backstop.

## Layer C — Multilingual semantic + classifier (opt-in)

For broad paraphrase coverage, enable the ML layers and use a **multilingual
model**:

```python
cfg = ScanConfig(profile="strict")   # enables semantic NN + a multilingual
                                     # embedding model automatically
# or, on the balanced profile:
cfg = ScanConfig(profile="balanced")
cfg.enable_semantic_nn = True
cfg.nn_model_name = "paraphrase-multilingual-MiniLM-L12-v2"   # or LaBSE
```

The default `all-MiniLM-L6-v2` is **English-only**; the coverage report's
`languages.semantic` field reports `english-only` vs `multilingual` so you
always know which you have.

## Layer D — Metadata

All layers run over the recursive metadata tree (XMP namespaces, custom
properties, property names). For PDFs, 0.5.0 also extracts text from
non-rendered surfaces — annotation `/Contents`, form `/V`, outlines, and
objects packed in compressed `/ObjStm` streams — so an injection hidden
there reaches Layers A–C.

## Knowing your coverage

```python
report = scanner.scan("incoming.pdf")
print(report.coverage["languages"])
# {'keyword_languages': ['ar','de',...], 'threat_keyword_languages': [...],
#  'script_agnostic': True, 'semantic': 'inactive', 'notes': '...'}
```

`keyword_languages` is exact-phrase **injection** (T4) coverage,
`threat_keyword_languages` is the **RAG-poisoning / social-engineering**
(T11/T12) coverage, `script_agnostic` covers hidden/metadata text in any
writing system, and `semantic` reflects the embedding model's breadth. The
scanner never claims a language it can't actually detect.

## Measuring it

`make benchmark` reports per-language and per-surface recall over the
in-tree multilingual corpus (`tests/multilingual_corpus_data.py`);
`scripts/benchmark_gate.py` fails the release if default-install multilingual
recall drops below 90% or any language hits zero.
