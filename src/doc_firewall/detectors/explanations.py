"""Human-language enrichment for findings.

The Finding objects produced by detectors carry concise technical `explain`
strings — useful for SIEM integration and log analysis, but unhelpful to a
non-technical reviewer who just wants to know "is this dangerous?"

This module post-processes a list of findings, replacing each recognised
finding's `explain` field with a plain-English version and moving the
original technical text to `technical_detail`. Findings the mapping does
not recognise are left untouched.

The mapping is centralised here (rather than scattered across detectors)
so the plain-language text can be reviewed and tuned without touching
detector logic. New finding types fall back gracefully — they keep their
existing `explain` text until someone adds an entry below.

Each entry follows the structure:

    {
      "match": <callable: (Finding) -> bool>,
      "explain": <plain-English: what was found and why a non-technical
                  reviewer should care>,
      "technical_detail": <optional override; if absent, the finding's
                          original explain is preserved as technical_detail>,
    }
"""
from __future__ import annotations

from typing import Callable

from ..enums import ThreatID
from ..report import Finding


# Type alias for clarity
_Matcher = Callable[[Finding], bool]


def _token_match(module_suffix: str, token: str) -> _Matcher:
    """Helper: match a fast-scan finding by module suffix + evidence['token']."""
    def _m(f: Finding) -> bool:
        return (
            (f.module or "").endswith(module_suffix)
            and (f.evidence or {}).get("token") == token
        )
    return _m


def _title_contains(needle: str) -> _Matcher:
    def _m(f: Finding) -> bool:
        return needle.lower() in (f.title or "").lower()
    return _m


def _module_and_title(module_suffix: str, title_needle: str) -> _Matcher:
    def _m(f: Finding) -> bool:
        return (
            (f.module or "").endswith(module_suffix)
            and title_needle.lower() in (f.title or "").lower()
        )
    return _m


# ── The enrichment table ──────────────────────────────────────────────────
#
# Order matters: the FIRST matching entry wins. Put narrow matchers above
# broader ones (e.g. specific-token matches above the catch-all "PDF active
# content" bundle).

_ENRICHMENTS: list[dict] = [
    # ── PDF token-level findings (fast_scan.pdf.tokens) ────────────────────

    {
        "match": _token_match("fast_scan.pdf.tokens", "/OpenAction"),
        "explain": (
            "This PDF is set up to run an action automatically the moment it's "
            "opened — before the reader sees any content. That action could be "
            "anything: opening another file, jumping to a URL, or (combined with "
            "other features below) launching an embedded script. Verify the file "
            "came from a trusted sender. If you don't know who sent it, do not open."
        ),
        "technical_detail": (
            "/OpenAction is a PDF dictionary key in the document catalog that "
            "specifies an action to execute on document open. By itself it can be "
            "benign (e.g. opening on a specific page). Combined with /JavaScript, "
            "/Launch, or /URI it becomes the trigger for executing code or fetching "
            "an external resource without user interaction. Common in exploit chains "
            "(e.g. CVE-2010-1240 used /OpenAction → /Launch for arbitrary command execution)."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/Encrypt"),
        "explain": (
            "This PDF is password-protected or DRM-protected. The scanner cannot "
            "read the actual content inside, which means hidden text, scripts, or "
            "embedded files (if any) cannot be checked. Treat the file as 'not "
            "fully verified' — open it only if you trust the sender."
        ),
        "technical_detail": (
            "/Encrypt indirect reference present in the trailer. Encryption may be "
            "password-based (user/owner) or certificate-based (PKI). Until the "
            "decryption key is supplied, content streams and embedded objects are "
            "opaque to static analysis. Attackers occasionally use encryption to "
            "smuggle malicious content past gateway scanners that don't have keys."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/Launch"),
        "explain": (
            "This PDF includes a feature that can launch an external program or "
            "open another file when triggered. Modern PDF readers disable this by "
            "default for security, but older readers (and some enterprise viewers) "
            "may still execute it. Do not open if the file is from an unknown sender."
        ),
        "technical_detail": (
            "/Launch is a PDF action type that runs an executable or opens a file. "
            "Used in real exploits (CVE-2010-1240 / Foxit, Adobe) to spawn arbitrary "
            "commands. Adobe Reader prompts the user before launching since v9; not "
            "all readers do."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/JavaScript"),
        "explain": (
            "This PDF contains embedded JavaScript code that can run inside the PDF "
            "reader. Even sandboxed, PDF JavaScript has been the carrier for many "
            "real-world exploits (Adobe Reader CVEs, font-parsing 0-days). Don't "
            "open if you don't trust the sender."
        ),
        "technical_detail": (
            "/JavaScript or /JS key in a PDF action / annotation / form field. PDF "
            "readers expose a restricted JS API but vulnerabilities in the engine "
            "(or in the readers parsing it) have led to RCE in the past. Combined "
            "with /OpenAction the script auto-runs on open."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/JS"),
        "explain": (
            "Same as /JavaScript above — this PDF carries embedded script code "
            "that the reader will execute. Open only from trusted senders."
        ),
        "technical_detail": (
            "/JS is the short form of /JavaScript inside a PDF action dictionary. "
            "See the /JavaScript entry above for full context."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/EmbeddedFile"),
        "explain": (
            "This PDF has another file packaged inside it (a document, executable, "
            "or archive). Attackers use this to smuggle malware past email or web "
            "scanners that only look at the outer PDF. Do not extract the embedded "
            "file unless you know what it is."
        ),
        "technical_detail": (
            "/EmbeddedFile (and the /Filespec / /F that references it) packages "
            "arbitrary file data inside the PDF. Used in real malware campaigns "
            "(e.g. various phishing droppers carrying secondary .doc / .xlsx / .exe "
            "payloads). PDF readers expose 'Attachments' that the user can extract."
        ),
    },
    {
        "match": _token_match("fast_scan.pdf.tokens", "/AA"),
        "explain": (
            "This PDF has Additional Actions configured — things that trigger "
            "automatically when you do something normal like clicking a field, "
            "tabbing between form fields, or even moving the mouse. Most resumes / "
            "forms with /AA are harmless (they're used for things like 'auto-format "
            "this date field'), but attackers can wire malicious scripts to these "
            "same triggers."
        ),
        "technical_detail": (
            "/AA = Additional Actions dictionary, supports triggers like /K "
            "(keystroke), /F (format), /V (validate), /C (calculate), /Fo (focus), "
            "/Bl (blur), /U (mouse up), /D (mouse down). Common in form-heavy PDFs "
            "(Adobe Acrobat exports) for benign field-formatting logic. Misuse path: "
            "/AA with /JavaScript that fires on a common user action."
        ),
    },

    # ── /AA found inside FlateDecode-compressed stream (T2/T3 evasion) ─────
    {
        "match": _module_and_title("fast_scan.pdf.flate", "/AA"),
        "explain": (
            "This PDF hides an Additional Actions trigger inside a compressed data "
            "stream — so simple text-search scanners won't see it. Inflating the "
            "stream revealed /AA, which means a script could fire when you interact "
            "with form fields. As above, most uses are benign Adobe form behaviour, "
            "but the compression is what makes it worth a second look."
        ),
        "technical_detail": (
            "/AA appears inside a FlateDecode-compressed object stream. FlateDecode "
            "is zlib compression — common for legitimate content but also used by "
            "exploit kits to evade signature scanners that don't decompress streams. "
            "We decompress and re-scan; the hit here is post-decompression."
        ),
    },

    # ── Catch-all PDF active-content indicator bundle ──────────────────────
    {
        "match": _module_and_title("pdf.active_content", "active-content indicators"),
        "explain": (
            "This PDF uses one or more PDF features that can run actions, scripts, "
            "or load external content. We've grouped them in one finding for "
            "summary; the specific tokens involved are listed in the evidence. "
            "If you trust the sender (Adobe Acrobat-exported form, e-signed "
            "document, etc.), this is usually fine."
        ),
        "technical_detail": (
            "Bundled fast-scan match for one or more of /JavaScript, /JS, "
            "/OpenAction, /AA, /Launch, /EmbeddedFile, /Filespec found in the raw "
            "PDF byte stream. Severity is HIGH if any high-risk token is present, "
            "MEDIUM otherwise. See the per-token enrichments above for what each "
            "specific token means."
        ),
    },

    # ── /URI suspicious URL scheme (BLOCK-class) ───────────────────────────
    {
        "match": _title_contains("PDF contains hyperlink with suspicious URL scheme"),
        "explain": (
            "This PDF contains a hyperlink that points to a JavaScript or data URL, "
            "a remote file-share, or an executable — the kind of target real "
            "attackers use to execute code or pull payloads when the link is "
            "clicked. Regular https:// or mailto: links are NOT flagged, and "
            "neither are leftover links to documents on the author's own machine. "
            "This finding alone is enough to block the file."
        ),
        "technical_detail": (
            "PDF /URI entries are matched against a deny-list: javascript:, data:, "
            "vbscript:, jar: schemes, raw IP-literal http(s) hosts, file:// URIs "
            "with a remote host (UNC / NTLM-credential-leak vector), and file:// "
            "URIs pointing at an executable. Plain http(s)/mailto/tel/sms URIs and "
            "local file:// document paths (Office→PDF export artifacts, reported "
            "separately as INFO) are explicitly excluded. This finding is marked "
            "verdict_class=BLOCK — single occurrence forces verdict=BLOCK."
        ),
    },

    # ── PDF Incremental Update Layers (INFO) ──────────────────────────────
    {
        "match": _module_and_title("fast_scan.pdf.structure", "Incremental Update Layers"),
        "explain": (
            "This PDF has been edited or re-saved at least once after it was first "
            "created. That's completely normal for any document a person has worked "
            "on (filled out a form, added a signature, made a correction). We note "
            "it for the record but it does not affect the verdict."
        ),
        "technical_detail": (
            "PDF allows incremental updates — the file ends with %%EOF, then a "
            "delta containing changed objects, then another %%EOF. Each save cycle "
            "adds one. A genuine PDF-shadow attack (one byte range shows benign "
            "content, the other malicious) requires correlated divergence between "
            "layers, which we don't measure here. INFO-class finding."
        ),
    },

    # ── ToUnicode CMap font-substitution heuristic (INFO) ─────────────────
    {
        "match": _module_and_title("pdf.obfuscation.cmap", "ToUnicode CMap"),
        "explain": (
            "This PDF uses embedded fonts (a font that ships inside the document, "
            "rather than relying on the reader's system fonts) — very common in any "
            "PDF exported from Word, InDesign, or LaTeX. A theoretical attack could "
            "use the same mechanism to make the visible text differ from what the "
            "scanner reads, but verifying that requires checking what's actually "
            "rendered on screen vs. what's extracted. We note the pattern; it does "
            "not affect the verdict."
        ),
        "technical_detail": (
            "ToUnicode CMap remaps glyph codes to Unicode code points; the heuristic "
            "fires when the remap ratio is high (most glyphs map to non-sequential "
            "code points), which is structurally indistinguishable from a benign "
            "subset font. Genuine font-substitution attacks need correlated "
            "rendered-vs-extracted text divergence. INFO-class finding."
        ),
    },

    # ── Stealth Unicode chars ─────────────────────────────────────────────
    {
        "match": _title_contains("Right-to-Left Override"),
        "explain": (
            "This document contains an invisible Right-to-Left Override character "
            "(U+202E). It's legitimately used in Arabic, Hebrew, and Persian text, "
            "but attackers also abuse it to disguise filenames — e.g. making "
            "'invoice[RLO]cod.exe' look like 'invoiceexe.cod' on screen. Worth a "
            "human's eyes on this file, especially if you weren't expecting "
            "right-to-left text."
        ),
        "technical_detail": (
            "U+202E (RIGHT-TO-LEFT OVERRIDE) found in extracted text or raw stream. "
            "Legitimate uses: Arabic/Hebrew/Farsi/Urdu content, bidirectional UI "
            "labels. Stealth uses: filename spoofing (CVE-1601), prompt-injection "
            "stealth (visually-reversed instructions)."
        ),
    },
    {
        "match": _title_contains("Zero Width Space"),
        "explain": (
            "This document contains invisible space characters (U+200B). They have "
            "legitimate uses in CJK typography and URL formatting, but they're also "
            "used to hide text from human reviewers while keeping it visible to AI "
            "systems — e.g. inserting an instruction into a resume that an "
            "ATS-screening LLM will read but a recruiter won't see."
        ),
        "technical_detail": (
            "U+200B (ZERO WIDTH SPACE) found in extracted text or raw stream. "
            "Legitimate uses: CJK line-break opportunities, breaking long URLs. "
            "Stealth uses: prompt-injection concealment, ATS keyword stuffing "
            "where extra spacing alters word boundaries that the LLM sees."
        ),
    },

    # ── Clip-path invisible text ───────────────────────────────────────────
    {
        "match": _title_contains("clip-path"),
        "explain": (
            "This PDF has text that is rendered into an empty region — so the text "
            "exists in the file (and any text-extracting tool, including AI "
            "summarisers, will read it) but it's invisible on screen. This is one "
            "of the techniques used to hide instructions in resumes that an "
            "AI-powered hiring system would see but a human wouldn't."
        ),
        "technical_detail": (
            "PDF clip-path operator 'W n' (clip + no-paint) preceding a BT (Begin "
            "Text) block. Sets the clipping region to nothing, then renders text "
            "into that nothing-region. Text is still discoverable via the content "
            "stream and any text-extraction library. T9 ATS-manipulation pattern."
        ),
    },

    # ── PII findings (T8) ─────────────────────────────────────────────────
    {
        "match": lambda f: (
            f.threat_id == ThreatID.T8_METADATA_INJECTION
            and "PII" in (f.title or "")
        ),
        "explain": (
            "This document contains personally identifiable information (PII) — "
            "things like phone numbers, email addresses, account numbers, or "
            "government IDs. Resumes, contracts, and many legitimate business "
            "documents naturally contain PII; this finding is a *notice*, not an "
            "accusation. Forward only over secure channels and consider whether "
            "the PII should be redacted before passing to third parties or LLMs."
        ),
        "technical_detail": (
            "PII regex bank matched in body text and/or metadata fields. Includes "
            "phone numbers, email addresses, SSN-shaped patterns, credit-card "
            "numbers (Luhn-validated), IBANs (ISO 3166-1 country-code validated), "
            "VINs (label-prefixed). Each match is categorised against HIPAA Safe-"
            "Harbor de-identification identifiers 1-18 — see evidence "
            "['hipaa_safe_harbor_hits'] for which identifier classes hit."
        ),
    },

    # ── Excessive metadata length (T8) ────────────────────────────────────
    {
        "match": _module_and_title("metadata_injection", "Excessive Metadata"),
        "explain": (
            "One of the document's metadata fields (like the author name or "
            "subject line) is unusually long — over 5 000 characters. Legitimate "
            "metadata fields are typically a few dozen characters. Very long "
            "fields can be an attempt to bury data inside metadata that a viewer "
            "won't show but an LLM or downstream parser will read."
        ),
        "technical_detail": (
            "Metadata field length exceeds 5 000 chars. Could be benign (some PDF "
            "generators embed full XML reports in metadata), or a buffer-overflow "
            "DoS attempt against parsers that don't impose length limits, or a "
            "data-smuggling carrier. We just flag the length; we don't claim it's "
            "malicious."
        ),
    },

    # ── EICAR signature ───────────────────────────────────────────────────
    {
        "match": _title_contains("EICAR"),
        "explain": (
            "This file contains the EICAR test string — an industry-standard "
            "test pattern used to verify antivirus software. If you're testing "
            "your scanner, congratulations: it works. If you didn't expect to "
            "see this, the file was crafted to test malware detection."
        ),
        "technical_detail": (
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE (68 bytes) — the standard test "
            "string defined by the European Institute for Computer Antivirus "
            "Research. Every legitimate AV product flags it. Always BLOCK-class."
        ),
    },

    # ── YARA match (T1) ───────────────────────────────────────────────────
    {
        "match": lambda f: (
            (f.module or "").startswith("yara") and "YARA Rule Match" in (f.title or "")
        ),
        "explain": (
            "This file matched a malware signature in our YARA rule database. "
            "Either a known malware family was detected, a known exploit pattern "
            "was recognised, or a custom rule for your environment fired. The "
            "rule name in the technical detail tells you which rule matched. "
            "Treat this as a high-confidence malware identification."
        ),
        "technical_detail": (
            "YARA pattern match. Rule metadata (see evidence['meta']) often "
            "includes the CVE, MITRE ATT&CK technique, and a description from "
            "the rule author. Always BLOCK-class — YARA hits are signature-based "
            "evidence."
        ),
    },

    # ── Antivirus engine hit (T1) ─────────────────────────────────────────
    {
        "match": _title_contains("Antivirus detection"),
        "explain": (
            "The configured antivirus engine (ClamAV, VirusTotal, or your custom "
            "AV) reported this file as infected. Treat as malware. The specific "
            "threat name from the AV engine is in the evidence."
        ),
        "technical_detail": (
            "External AV verdict = infected. Engine-specific result in evidence. "
            "Always BLOCK-class."
        ),
    },
]


# ── Threat-level plain-English fallback (covers ALL 12 threats) ────────────
#
# The specific `_ENRICHMENTS` above only recognise ~20 finding shapes. Every
# OTHER finding used to keep the detector's raw `explain` — often jargon
# ("Score 7.0 >= 2.0", "Token 'python' appears in 25% of all words"). This
# table guarantees that any finding, for any of T1–T12, gets a clear "what we
# found and why it matters" sentence a non-technical reader can act on. The
# detector's original text is preserved in `technical_detail`.
_THREAT_FALLBACKS: dict[ThreatID, str] = {
    ThreatID.T1_MALWARE: (
        "Part of this file matches a known-malware signature — it looks like "
        "something already identified as malicious. Treat the file as dangerous: "
        "don't open or run it, and don't pass it to other systems."
    ),
    ThreatID.T2_ACTIVE_CONTENT: (
        "This file can run code or actions on its own — scripts, auto-open "
        "actions, or macros. A document you only need to read shouldn't have to "
        "run programs. Open it only if you trust whoever sent it."
    ),
    ThreatID.T3_OBFUSCATION: (
        "Part of this document is hidden or disguised — text made invisible, "
        "characters swapped to look like others, or content arranged to fool "
        "automated readers. Hiding text is a common way to slip instructions "
        "past a human while an AI still reads them."
    ),
    ThreatID.T4_PROMPT_INJECTION: (
        "This document contains text that tries to give instructions to an AI "
        "assistant — for example telling it to ignore its rules or reveal hidden "
        "information. If an AI reads this document, it may obey the planted "
        "instructions instead of you."
    ),
    ThreatID.T5_RANKING_MANIPULATION: (
        "This document repeats words or phrases in an unnatural way to trick a "
        "search or AI-retrieval system into ranking it higher than it deserves."
    ),
    ThreatID.T6_DOS: (
        "This file is built in a way that can overwhelm the software that opens "
        "it — for example expanding to a huge size or looping forever — which "
        "can freeze or crash a system."
    ),
    ThreatID.T7_EMBEDDED_PAYLOAD: (
        "Another file is hidden inside this one, such as a program or archive. "
        "This is a common way to smuggle malware past scanners that only check "
        "the outer file. Don't extract it unless you know exactly what it is."
    ),
    ThreatID.T8_METADATA_INJECTION: (
        "This document carries extra information in its hidden properties — "
        "either sensitive personal data, or content placed where a viewer won't "
        "show it but an automated reader (like an AI) still will."
    ),
    ThreatID.T9_ATS_MANIPULATION: (
        "This document — often a résumé — is stuffed with repeated keywords or "
        "hidden text designed to trick automated screening systems into scoring "
        "it higher than it should."
    ),
    ThreatID.T10_INDIRECT_INJECTION: (
        "This document points to an outside location (a link or remote file) "
        "together with an instruction to go fetch it — a way to pull in "
        "malicious content or instructions from somewhere else."
    ),
    ThreatID.T11_RAG_POISONING: (
        "This document contains text designed to manipulate an AI knowledge "
        "base — for example claiming to be the only trustworthy source so the "
        "AI ignores other documents when answering."
    ),
    ThreatID.T12_SOCIAL_ENGINEERING: (
        "This document uses pressure tactics common in scams and phishing — "
        "urgency, pretending to be an authority, or demands to pay money or "
        "hand over passwords."
    ),
}


def _apply_threat_fallback(f: Finding) -> None:
    """Give an un-enriched finding a plain, threat-level explanation while
    preserving its original technical text. Skips findings a detector has
    already written a plain `evidence['plain_english']` for."""
    base = _THREAT_FALLBACKS.get(f.threat_id)
    if not base:
        return
    ev = f.evidence or {}
    # The detector already produced a plain, self-contained explanation.
    if isinstance(ev.get("plain_english"), str) and ev["plain_english"].strip():
        return
    f.technical_detail = f.technical_detail or f.explain
    mt = ev.get("malicious_text")
    if isinstance(mt, str) and mt.strip():
        base += " The exact text we flagged is shown in this finding's evidence."
    f.explain = base


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    """Mutate `findings` in place to add plain-language explanations.

    1. If a finding matches a specific entry in `_ENRICHMENTS`, its `explain`
       is replaced with that entry's plain-English text (original →
       `technical_detail`).
    2. Otherwise a threat-level fallback (`_THREAT_FALLBACKS`, one per T1–T12)
       gives it a clear plain explanation — so NO finding is left showing only
       raw detector jargon. Findings the detector already wrote plain
       (`evidence['plain_english']`) keep their text.
    """
    for f in findings:
        matched = False
        for entry in _ENRICHMENTS:
            try:
                if entry["match"](f):
                    f.technical_detail = entry.get("technical_detail") or f.explain
                    f.explain = entry["explain"]
                    matched = True
                    break
            except Exception:
                # Matchers should never raise, but be defensive — a broken
                # entry must not crash the scanner.
                continue
        if not matched:
            _apply_threat_fallback(f)
    return findings
