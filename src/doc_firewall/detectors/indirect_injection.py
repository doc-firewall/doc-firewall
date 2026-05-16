from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

# Signal A: external reference patterns
_URL_RE = re.compile(r'https?://[^\s\'"<>]{8,}', re.IGNORECASE)
_UNIX_PATH_RE = re.compile(r'/[a-z_][a-z0-9_-]*/[a-z0-9_./-]{2,}', re.IGNORECASE)
_WIN_PATH_RE = re.compile(r'[A-Z]:\\[^\s\\]{2,}(?:\\[^\s\\]+)+', re.IGNORECASE)

# D.11: Extended URI vocabulary — non-https schemes attackers use to evade
# the simple `https?://` check.
_EXT_URI_RE = re.compile(
    r'\b(?:'
    r'data:[a-z]+/[a-z0-9.+-]+(?:;[^,\s]+)?,'         # data: URIs
    r'|file://[/\\][^\s\'"<>]{2,}'                     # file:// paths
    r'|smb://[^\s\'"<>]{4,}'                           # SMB
    r'|ipfs://[A-Za-z0-9]{4,}'                         # IPFS
    r'|ipns://[A-Za-z0-9]{4,}'                         # IPNS
    r'|gopher://[^\s\'"<>]{4,}'                        # Gopher
    r'|dict://[^\s\'"<>]{4,}'                          # Dict
    r'|ldap://[^\s\'"<>]{4,}'                          # LDAP
    r'|ftp://[^\s\'"<>]{4,}'                           # FTP
    r'|sftp://[^\s\'"<>]{4,}'                          # SFTP
    r')',
    re.IGNORECASE,
)
# UNC paths (Windows / SMB) — \\server\share or \\?\UNC\server\share
_UNC_PATH_RE = re.compile(
    r'\\\\(?:\?\\UNC\\)?[A-Za-z0-9_.-]{2,}\\[A-Za-z0-9_.\\$-]{2,}'
)
# GitHub / Gist raw — high-confidence staging hosts
_STAGING_URL_RE = re.compile(
    r'\b(?:'
    r'raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[\w.-]+/[\w./-]+'
    r'|gist\.githubusercontent\.com/[\w.-]+/[\w.-]+/raw/[\w./-]+'
    r'|pastebin\.com/raw/[A-Za-z0-9]+'
    r')',
    re.IGNORECASE,
)

# Agent tool-call schemas with external path context
# Matches XML-style tool_use/tool_call blocks whose content references a URL or file path
_TOOL_CALL_OPEN_RE = re.compile(
    r'<tool(?:_use|_call|_invoke)?>.*?<name>[^<]*(?:read_file|get_webpage|fetch|download|'
    r'load_url|retrieve|http_get|browse|open_url|web_search)[^<]*</name>',
    re.IGNORECASE | re.DOTALL,
)
# JSON/Python-style function call with fetch-like name
_TOOL_CALL_FUNC_RE = re.compile(
    r'\bfunction_call\s*[({]\s*["\']?(?:read_file|get_webpage|fetch|download|load_url|'
    r'retrieve|http_get|browse|open_url)\b',
    re.IGNORECASE,
)

# Signal B: fetch/instruction verbs
_FETCH_VERBS_RE = re.compile(
    r'\b(?:fetch|retrieve|download|load\s+from|read\s+from|'
    r'execute\s+instructions?\s+from|import\s+from|get\s+from|pull\s+from|'
    r'follow\s+the\s+instructions?\s+(?:at|from|in)|see\s+also)\b',
    re.IGNORECASE,
)

# T4 anchor phrases for HIGH-severity escalation
_T4_ANCHORS_RE = re.compile(
    r'\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?|'
    r'system\s+prompt|disregard|you\s+are\s+now|'
    r'override\s+(?:all\s+)?(?:instructions?|rules?|safety|restrictions?|filters?)|'
    r'rank\s+(?:this|me|first)|forget\s+(?:all\s+)?(?:previous|prior)|'
    r'new\s+instructions?|jailbreak|developer\s+mode|admin\s+override)\b',
    re.IGNORECASE,
)

_WINDOW = 500


def _find_signal_a(text: str) -> list[tuple[int, int, str]]:
    """Return all (start, end, matched_text) Signal A (external ref) hits."""
    hits: list[tuple[int, int, str]] = []
    for pattern in (_URL_RE, _UNIX_PATH_RE, _WIN_PATH_RE,
                    _EXT_URI_RE, _UNC_PATH_RE, _STAGING_URL_RE):
        for m in pattern.finditer(text):
            hits.append((m.start(), m.end(), m.group()))
    return hits


class IndirectInjectionDetector(Detector):
    """C.1 — T10: Indirect / Multi-Hop Prompt Injection detection.

    Fires when a document instructs an AI agent to fetch external content that
    may contain a malicious payload. Two signals are required to fire: an
    external reference (URL / file path) co-located within 500 chars of a
    fetch/load instruction verb. Tool-call schemas referencing external paths
    fire HIGH directly without requiring Signal B.
    """

    name = "indirect_injection"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_indirect_injection", True):
            return []

        findings: List[Finding] = []
        text = doc.text or ""
        if not text:
            return findings

        # D.11: UNC / SMB paths and staging-URL hosts (raw.githubusercontent,
        # gist raw, pastebin raw) fire HIGH on their own — no legitimate
        # document needs a UNC instruction or a raw GitHub URL embedded as a
        # fetch directive.
        for label, pattern, subtype, objective in [
            (
                "Indirect Injection — SMB / UNC Path Reference",
                _UNC_PATH_RE,
                "unc_path",
                "Multi-hop injection via SMB / UNC share",
            ),
            (
                "Indirect Injection — Staging Host (raw GitHub / Gist / Pastebin)",
                _STAGING_URL_RE,
                "staging_host",
                "Multi-hop injection via known payload-staging service",
            ),
        ]:
            m = pattern.search(text)
            if m:
                snippet = text[
                    max(0, m.start() - 50): min(len(text), m.end() + 200)
                ].strip()
                findings.append(Finding(
                    threat_id=ThreatID.T10_INDIRECT_INJECTION,
                    severity=Severity.HIGH,
                    title=label,
                    explain=(
                        f"Document contains '{m.group()[:80]}'. This URI class "
                        "is rarely used in legitimate documents and is a high-"
                        "signal indicator of a multi-hop injection / payload "
                        "staging chain."
                    ),
                    evidence={
                        "subtype": subtype,
                        "external_ref": m.group()[:120],
                        "snippet": snippet[:200],
                        "malicious_text": snippet[:250],
                    },
                    module=self.name,
                    confidence=0.85,
                    mitre_technique="T1071",
                    attack_objective=objective,
                ))
                return findings

        # ── Tool-call schema path (HIGH, no proximity requirement) ─────────
        for pattern in (_TOOL_CALL_OPEN_RE, _TOOL_CALL_FUNC_RE):
            m = pattern.search(text)
            if m:
                start = m.start()
                window = text[max(0, start - _WINDOW): start + _WINDOW]
                if _URL_RE.search(window) or _UNIX_PATH_RE.search(window) or _WIN_PATH_RE.search(window):
                    snippet = text[max(0, start - 50): min(len(text), start + 200)].strip()
                    findings.append(Finding(
                        threat_id=ThreatID.T10_INDIRECT_INJECTION,
                        severity=Severity.HIGH,
                        title="Indirect Injection via Agent Tool-Call Schema",
                        explain=(
                            "Document embeds an agent tool-call schema (read_file / get_webpage / "
                            "fetch) referencing an external URL or file path. An autonomous agent "
                            "processing this document may retrieve and execute attacker-controlled "
                            "instructions from the referenced location."
                        ),
                        evidence={"snippet": snippet[:200], "malicious_text": snippet[:250]},
                        module=self.name,
                        confidence=0.90,
                        mitre_technique="T1071",
                        attack_objective="Multi-hop prompt injection via agent tool-call to external resource",
                    ))
                    return findings

        # ── Two-signal co-occurrence path (Signal A + Signal B) ────────────
        for a_start, a_end, a_text in _find_signal_a(text):
            win_start = max(0, a_start - _WINDOW)
            win_end = min(len(text), a_end + _WINDOW)
            window = text[win_start:win_end]

            if not _FETCH_VERBS_RE.search(window):
                continue

            # Determine severity: escalate to HIGH if a T4 anchor is also present
            if _T4_ANCHORS_RE.search(window):
                severity = Severity.HIGH
                title = "Indirect Injection with Prompt Injection Anchor"
                explain = (
                    f"External reference '{a_text[:80]}' co-located within 500 characters of "
                    "a fetch/load verb AND a prompt injection anchor phrase. High-confidence "
                    "multi-hop injection attempt targeting an autonomous agent."
                )
                confidence = 0.90
            else:
                severity = Severity.MEDIUM
                title = "Indirect Injection Reference (External URL + Fetch Verb)"
                explain = (
                    f"Document references an external resource ('{a_text[:80]}') within "
                    "500 characters of a fetch/load instruction verb. An autonomous agent "
                    "acting on this document may retrieve malicious instructions from the "
                    "external location."
                )
                confidence = 0.75

            snippet = text[win_start: min(len(text), win_start + 300)].strip()
            findings.append(Finding(
                threat_id=ThreatID.T10_INDIRECT_INJECTION,
                severity=severity,
                title=title,
                explain=explain,
                evidence={
                    "external_ref": a_text[:100],
                    "snippet": snippet[:200],
                    "malicious_text": snippet[:250],
                },
                module=self.name,
                confidence=confidence,
                mitre_technique="T1071",
                attack_objective="Multi-hop prompt injection — agent fetches payload from external resource",
            ))
            break  # One finding per document

        return findings
