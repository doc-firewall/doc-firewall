from __future__ import annotations

import re
from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID, VerdictClass
from ..report import Finding
from ..utils.unicode_norm import normalize_text
from .base import Detector, pattern_cache_key


def _looks_like_text(content: str, min_printable_ratio: float = 0.85) -> bool:
    """True when content is plausibly natural language.

    PDF metadata extractors occasionally leak undecoded compressed /
    encrypted stream bytes into fields like /Author or /Keywords. Short
    SQL-injection regexes (``1=1``, ``select *``) happily match coincidental
    byte sequences in that noise (an EICAR-shaped FP). Gate all regex-based
    metadata checks on this so they only run against fields that actually
    look like text. The length-based DoS check is exempt — it counts bytes
    regardless of content.
    """
    if not content:
        return False
    printable = sum(
        1 for c in content
        if c.isprintable() or c in "\t\n\r"
    )
    return (printable / len(content)) >= min_printable_ratio


def _collect_metadata_strings(meta, _depth: int = 0, _budget: list | None = None) -> List[str]:
    """H.15 (0.4.8): recursively flatten every string in a metadata tree —
    nested dicts (XMP namespaces), lists (multi-valued properties), AND dict
    keys (an injection can hide in a custom property name). Bounded against
    pathological metadata: depth 6, 2000 collected strings.
    """
    if _budget is None:
        _budget = [2000]
    out: List[str] = []
    if _depth > 6 or _budget[0] <= 0:
        return out
    if isinstance(meta, str):
        if meta:
            out.append(meta)
            _budget[0] -= 1
    elif isinstance(meta, dict):
        for k, v in meta.items():
            if isinstance(k, str) and k:
                out.append(k)          # scan property names too
                _budget[0] -= 1
            out.extend(_collect_metadata_strings(v, _depth + 1, _budget))
            if _budget[0] <= 0:
                break
    elif isinstance(meta, (list, tuple, set)):
        for item in meta:
            out.extend(_collect_metadata_strings(item, _depth + 1, _budget))
            if _budget[0] <= 0:
                break
    return out


def _centered_snippet(content: str, m: re.Match, before: int = 60, after: int = 190) -> str:
    """Snippet centered on the regex match — the evidence must contain the
    matched content, not the head of the field (H.3, 0.4.8)."""
    start = max(0, m.start() - before)
    return content[start: min(len(content), m.end() + after)].strip()


# SQL tokens for the metadata heuristic. A single token (especially "1=1" or
# "select *") matches coincidental punctuation in PDF-generator noise; the
# finding now requires either two distinct tokens or one token plus SQL
# statement punctuation (quote/semicolon/comment) in the same field.
_SQL_TOKEN_RE = re.compile(
    r"drop\s+table|select\s+\*|union\s+select|insert\s+into|delete\s+from|"
    r"exec(?:ute)?\s+xp_|;\s*--|'\s*or\s+'?1'?\s*=\s*'?1",
    re.IGNORECASE,
)
_SQL_CONTEXT_RE = re.compile(r"[';]|--\s|\bfrom\b|\bwhere\b", re.IGNORECASE)


class MetadataInjectionDetector(Detector):
    name = "metadata_injection"

    def _ensure_compiled(self, config: ScanConfig) -> None:
        """G.4: content-hash-keyed compile (replaces id(config) check)."""
        key = pattern_cache_key(config.prompt_injection_patterns)
        if getattr(self, "_compiled_key", None) == key and hasattr(
            self, "_compiled_pi_patterns"
        ):
            return
        self._compiled_pi_patterns = [
            re.compile(pat, re.IGNORECASE)
            for _cat, rules in config.prompt_injection_patterns.items()
            for pat, _weight in rules
        ]
        self._compiled_key = key

    def prepare(self, config: ScanConfig) -> None:
        if config.enable_metadata_checks:
            self._ensure_compiled(config)

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_metadata_checks:
            return []

        findings = []

        # Gather all metadata-like content. H.15 (0.4.8): walk the whole
        # metadata tree (nested dicts from XMP namespaces, list-valued custom
        # properties, and the field NAMES themselves) rather than a fixed
        # field allow-list with a string-only fallback — injections hide in
        # custom XMP fields and even in property keys, and the old gather
        # silently dropped non-string / non-"comments"-list values.
        # `hex_blobs` holds binary artifacts (e.g. a PDF digital-signature
        # PKCS#7 blob) surfaced for the T7 embedded-payload detector. They are
        # not metadata text — scanning them here double-flagged digitally-signed
        # PDFs (excessive-length + coincidental regex hits) on the benign corpus.
        meta_for_t8 = doc.metadata
        if isinstance(doc.metadata, dict) and "hex_blobs" in doc.metadata:
            meta_for_t8 = {k: v for k, v in doc.metadata.items() if k != "hex_blobs"}
        targets: List[str] = _collect_metadata_strings(meta_for_t8)

        # Also check docx specific fields if not already in metadata
        if doc.docx:
            if "comments" in doc.docx:
                targets.extend(
                    c for c in doc.docx["comments"] if isinstance(c, str)
                )

        # T8 Checks
        for content in targets:
            if not content:
                continue

            # 1. Length check (Buffer overflow / DoS vector via metadata)
            if len(content) > 5000:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.HIGH,
                        title="Excessive Metadata/Comment Length",
                        explain=(
                            "Found metadata or comment field exceeding 5000 characters."
                        ),
                        evidence={"length": len(content), "snippet": content[:50], "malicious_text": content[:250]},
                        module=self.name,
                        confidence=0.8,
                    )
                )

            # All remaining checks below are regex-based and prone to
            # coincidental matches in undecoded PDF stream bytes. Skip
            # non-text content entirely.
            if not _looks_like_text(content):
                continue

            # 2. Syntax Injection (HTML/JS)
            m_js = re.search(
                r"<script|javascript:|vbscript:|onload=|onerror=",
                content,
                re.IGNORECASE,
            )
            if m_js:
                snippet = _centered_snippet(content, m_js)
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Script Injection in Metadata",
                        explain=(
                            "Detailed script tags or event handlers found "
                            "in metadata/comments."
                        ),
                        evidence={
                            "match": m_js.group(0)[:80],
                            "snippet": snippet[:100],
                            "malicious_text": snippet[:250],
                        },
                        module=self.name,
                        confidence=1.0,
                        # <script> / javascript:/vbscript: / onload=/onerror=
                        # in a metadata field that already passed the printable-
                        # text gate above has no legitimate use — definitive.
                        verdict_class=VerdictClass.BLOCK,
                    )
                )

            # SQL-like syntax in metadata (H.3, 0.4.8). This is a heuristic,
            # not a confirmed injection: a single token like "select *" in
            # binary-ish generator noise was a recurring FP, and the HIGH/0.9
            # "SQL Injection" label overstated the evidence. Require a second
            # distinct token or SQL statement punctuation, report at MEDIUM,
            # and center the evidence on the match so reviewers see the SQL.
            sql_matches = list(_SQL_TOKEN_RE.finditer(content))
            if sql_matches and (
                len({m.group(0).lower() for m in sql_matches}) >= 2
                or _SQL_CONTEXT_RE.search(content)
            ):
                m_sql = sql_matches[0]
                snippet = _centered_snippet(content, m_sql)
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.MEDIUM,
                        title="SQL-like Syntax in Metadata",
                        explain=(
                            "Metadata field contains SQL-statement-like syntax. "
                            "This is a heuristic signal — it matters when the "
                            "document is ingested by a pipeline that interpolates "
                            "metadata into queries; it is not proof of an attack."
                        ),
                        evidence={
                            "match": m_sql.group(0)[:80],
                            "all_matches": [m.group(0)[:60] for m in sql_matches[:5]],
                            "snippet": snippet[:100],
                            "malicious_text": snippet[:250],
                        },
                        module=self.name,
                        confidence=0.6,
                    )
                )

            # 3. Prompt Injection in Metadata (T8/T4 crossover)
            # Run the full compiled T4 pattern set (from ScanConfig) on each
            # metadata field rather than a short hardcoded list of 9 patterns.
            # Injections placed in PDF /Keywords or DOCX description that use
            # any of the 50+ T4 regexes are caught here.
            normalized = normalize_text(content)
            self._ensure_compiled(config)

            for compiled_pat in self._compiled_pi_patterns:
                m = compiled_pat.search(normalized)
                if m:
                    # Center evidence on the match (positions are in the
                    # normalized text, so slice that, not the raw field).
                    snippet = _centered_snippet(normalized, m)
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T8_METADATA_INJECTION,
                            severity=Severity.HIGH,
                            title="Prompt Injection in Metadata",
                            explain=(
                                "Potentially malicious instructions found in "
                                "document metadata. Metadata is a common injection "
                                "surface for documents processed by LLM/RAG pipelines."
                            ),
                            evidence={
                                "snippet": snippet[:100],
                                "match": m.group(0)[:80],
                                "malicious_text": snippet[:250],
                            },
                            module=self.name,
                            confidence=0.9,
                        )
                    )
                    break

        return findings
