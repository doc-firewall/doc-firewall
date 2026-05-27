from __future__ import annotations
import re
from typing import List
from .base import Detector, pattern_cache_key
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity, VerdictClass
from ..utils.unicode_norm import normalize_text


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

        # Gather all metadata-like content
        targets: List[str] = []
        if doc.metadata:
            for k, v in doc.metadata.items():
                if k in [
                    "title",
                    "subject",
                    "creator",
                    "description",
                    "lastModifiedBy",
                ] and isinstance(v, str):
                    targets.append(v)
                elif k == "comments" and isinstance(v, list):
                    targets.extend(v)
                elif isinstance(v, str):
                    # fallback for other fields
                    targets.append(v)

        # Also check docx specific fields if not already in metadata
        if doc.docx:
            if "comments" in doc.docx:
                targets.extend(doc.docx["comments"])

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
            if re.search(
                r"<script|javascript:|vbscript:|onload=|onerror=",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.CRITICAL,
                        title="Script Injection in Metadata",
                        explain=(
                            "Detailed script tags or event handlers found "
                            "in metadata/comments."
                        ),
                        evidence={"snippet": content[:100], "malicious_text": content[:250]},
                        module=self.name,
                        confidence=1.0,
                        # <script> / javascript:/vbscript: / onload=/onerror=
                        # in a metadata field that already passed the printable-
                        # text gate above has no legitimate use — definitive.
                        verdict_class=VerdictClass.BLOCK,
                    )
                )

            # SQL Injection in Metadata
            if re.search(
                r"drop\s+table|select\s+\*|union\s+select|insert\s+into|1=1",
                content,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T8_METADATA_INJECTION,
                        severity=Severity.HIGH,
                        title="SQL Injection in Metadata",
                        explain="Found SQL injection syntax in metadata.",
                        evidence={"snippet": content[:100], "malicious_text": content[:250]},
                        module=self.name,
                        confidence=0.9,
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
                                "snippet": content[:100],
                                "match": m.group(0)[:80],
                                "malicious_text": content[:250],
                            },
                            module=self.name,
                            confidence=0.9,
                        )
                    )
                    break

        return findings
