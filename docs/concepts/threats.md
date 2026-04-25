---
title: Threat Model — T1 to T9 Document Threat Taxonomy
description: DocFirewall's threat taxonomy covers 9 attack vectors: T1 Malware, T2 Active Content, T3 Obfuscation, T4 Prompt Injection, T5 Ranking Manipulation, T6 DoS, T7 Embedded Payloads, T8 Metadata Injection, and T9 ATS Manipulation.
---

# Threat Model

DocFirewall maps its defenses to specific Threat IDs (T-Codes).

| ID | Name | Description | Severity |
|---|---|---|---|
| T1 | Malware | Traditional viruses, trojans, ransomware. | Critical |
| T2 | Active Content | Executable scripts (JS, VBA) that run on open. | Critical |
| T3 | Obfuscation | Hiding content to bypass filters (homoglyphs, invisible text). | High |
| T4 | Prompt Injection | Instructions designed to hijack LLM behavior. | High |
| T5 | Ranking Manipulation | Keyword stuffing to game RAG retrieval. | Medium |
| T6 | Denial of Service | Resources exhaustion (Zip bombs, infinite loops). | High |
| T7 | Embedded Payloads | Binaries hidden in object streams. | High |
| T8 | Metadata Injection | Exploits in document properties. | Medium |
| T9 | ATS Manipulation | Resumes optimized for machines, not humans. | Low |
