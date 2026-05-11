"""C.3 — T12: Social Engineering detector.

Tri-signal co-occurrence model — a finding requires at least two of three
signals present within a 600-character window:

  Signal A  Urgency / scarcity cues  ("immediately", "within 24 hours", "urgent")
  Signal B  Authority / identity claims  ("IT department", "CEO", "legal team")
  Signal C  Action demands  ("click the link", "wire transfer", "provide your credentials")

Single-signal pattern overrides (HIGH without proximity check):
  • Bank routing / IBAN / account-number patterns
  • Credential-harvesting prompts ("enter your password", "submit your SSN")
  • Fake legal threats  ("you will be prosecuted", "arrest warrant")

MITRE ATT&CK: T1566 — Phishing.
"""
from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity

_WINDOW = 600
_MITRE = "T1566"

# ── Signal A: Urgency / scarcity ──────────────────────────────────────────────

_URGENCY_RE = re.compile(
    r'\b(?:immediately|urgent(?:ly)?|right\s+away|as\s+soon\s+as\s+possible|asap|'
    r'within\s+(?:24|48|72|2|3)\s+hours?|by\s+end\s+of\s+(?:day|business)|'
    r'time\s*[–\-]\s*sensitive|action\s+required|respond\s+(?:now|today|immediately)|'
    r'failure\s+to\s+(?:respond|comply|act)|your\s+account\s+(?:will\s+be\s+)?'
    r'(?:suspended|terminated|locked|deactivated|closed)|'
    r'limited\s+time|expire[sd]?|last\s+chance|final\s+notice|'
    r'critical\s+(?:alert|notice|update|warning))\b',
    re.IGNORECASE,
)

# ── Signal B: Authority / identity claims ────────────────────────────────────

_AUTHORITY_RE = re.compile(
    r'\b(?:IT\s+(?:department|team|support|helpdesk|security)|'
    r'(?:the\s+)?(?:CEO|CFO|COO|CTO|CISO|CXO|president|director|manager|supervisor|'
    r'HR|human\s+resources|payroll|finance|accounting|treasury|legal\s+(?:team|department)|'
    r'compliance\s+(?:team|department)|board\s+of\s+directors)|'
    r'(?:your\s+)?(?:bank|credit\s+union|financial\s+institution)|'
    r'(?:IRS|FBI|INTERPOL|Europol|police|sheriff|attorney\s+general|court|'
    r'law\s+enforcement|government\s+(?:agency|official)|'
    r'Microsoft|Apple|Google|Amazon|PayPal|Netflix)|'
    r'tech(?:nical)?\s+support|customer\s+(?:service|support)|'
    r'(?:your\s+)?account\s+(?:team|manager|representative))\b',
    re.IGNORECASE,
)

# ── Signal C: Action demands ──────────────────────────────────────────────────

_ACTION_RE = re.compile(
    r'\b(?:click\s+(?:the\s+|this\s+)?(?:link|here|button|attachment|below)|'
    r'open\s+(?:the\s+)?attachment|download\s+(?:the\s+)?(?:file|attachment|update)|'
    r'wire\s+transfer|transfer\s+(?:the\s+)?(?:funds?|money|amount)|'
    r'provide\s+(?:your\s+)?(?:password|credentials?|login|username|pin|'
    r'social\s+security|ssn|bank\s+(?:account|details?|information)|'
    r'credit\s+card|card\s+(?:number|details?|information))|'
    r'(?:enter|input|type|submit|send)\s+(?:your\s+)?(?:password|credentials?|'
    r'login|pin|ssn|social\s+security|otp|verification\s+code|'
    r'bank\s+(?:account|details?)|credit\s+card)|'
    r'call\s+(?:this\s+number|us\s+(?:now|immediately|at))|'
    r'reply\s+with\s+(?:your\s+)?(?:password|code|pin|ssn|account)|'
    r'verify\s+(?:your\s+)?(?:account|identity|information|details?)|'
    r'confirm\s+(?:your\s+)?(?:account|identity|details?|password)|'
    r'install\s+(?:this\s+)?(?:software|app|update|tool|remote\s+access)|'
    r'grant\s+(?:remote\s+)?(?:access|permission|control))\b',
    re.IGNORECASE,
)

# ── High-confidence single-signal overrides ───────────────────────────────────

# Bank account / routing / IBAN patterns
_BANK_ACCOUNT_RE = re.compile(
    r'\b(?:'
    r'routing\s+(?:number|#|no\.?)[\s:]*\d{6,9}|'         # US ABA routing
    r'account\s+(?:number|#|no\.?)[\s:]*\d{6,17}|'         # Bank account
    r'IBAN[\s:]*[A-Z]{2}\d{2}[\s]?[\dA-Z]{4,30}|'          # IBAN
    r'SWIFT[\s/]BIC[\s:]*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?|'  # SWIFT/BIC
    r'wire\s+(?:funds?|money|transfer)[\s\w]{0,30}?'
    r'(?:routing|account|IBAN|SWIFT)\b'
    r')',
    re.IGNORECASE,
)

# Credential harvesting prompts
_CREDENTIAL_HARVEST_RE = re.compile(
    r'\b(?:'
    r'(?:enter|type|provide|send|submit|reply\s+with)\s+(?:your\s+)?'
    r'(?:password|social\s+security\s+number|ssn|credit\s+card\s+number|'
    r'full\s+card\s+(?:number|details?)|cvv|card\s+verification|pin\s+(?:number|code)|'
    r'one[-\s]time\s+(?:password|code|pin)|otp|'
    r'mother\'?s\s+maiden\s+name|date\s+of\s+birth|dob)|'
    r'(?:username|password)\s+(?:below|above|here|in\s+(?:this|the)\s+(?:form|field|box))'
    r')',
    re.IGNORECASE,
)

# Fake legal threats
_LEGAL_THREAT_RE = re.compile(
    r'\b(?:'
    r'(?:will\s+be|are\s+subject\s+to|face[sd]?)\s+'
    r'(?:prosecut(?:ed|ion)|arrest(?:ed)?|criminal\s+charges?|'
    r'civil\s+(?:action|lawsuit|penalties?)|federal\s+charges?|'
    r'legal\s+action|(?:heavy\s+)?(?:fines?|penalties?))|'
    r'arrest\s+warrant|warrant\s+for\s+(?:your\s+)?arrest|'
    r'(?:legal|criminal)\s+proceedings?\s+(?:have\s+been\s+)?(?:initiated|filed|commenced)|'
    r'(?:your\s+)?assets?\s+(?:will\s+be\s+|are\s+being\s+)?(?:frozen|seized|confiscated)'
    r')',
    re.IGNORECASE,
)


def _find_signal_positions(pattern: re.Pattern[str], text: str) -> list[int]:
    """Return start positions of all matches."""
    return [m.start() for m in pattern.finditer(text)]


class SocialEngineeringDetector(Detector):
    """C.3 — T12: Social Engineering / Phishing detection.

    Fires on tri-signal co-occurrence (A+B or A+C or B+C within 600 chars)
    or on high-confidence single-signal overrides (bank numbers, credential
    harvesting, fake legal threats).
    """

    name = "social_engineering"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not getattr(config, "enable_social_engineering", True):
            return []

        findings: List[Finding] = []
        text = doc.text or ""
        if not text:
            return findings

        # ── High-confidence single-signal overrides (HIGH without proximity) ─
        for label, pattern, objective in [
            (
                "Credential Harvesting — Sensitive Data Request",
                _CREDENTIAL_HARVEST_RE,
                "Harvest user credentials or PII via social engineering",
            ),
            (
                "Social Engineering — Fake Legal Threat",
                _LEGAL_THREAT_RE,
                "Coerce victim compliance via fabricated legal consequences",
            ),
            (
                "Social Engineering — Bank Account / Wire Transfer Details",
                _BANK_ACCOUNT_RE,
                "Redirect financial transactions via social engineering",
            ),
        ]:
            m = pattern.search(text)
            if m:
                snippet = text[max(0, m.start() - 100): min(len(text), m.end() + 200)].strip()
                findings.append(Finding(
                    threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
                    severity=Severity.HIGH,
                    title=label,
                    explain=(
                        f"Document contains a high-confidence social engineering signal: "
                        f"'{m.group()[:80]}'. This pattern is strongly associated with "
                        "phishing, fraud, or credential harvesting attacks."
                    ),
                    evidence={
                        "matched_text": m.group()[:100],
                        "snippet": snippet[:250],
                        "malicious_text": snippet[:300],
                    },
                    module=self.name,
                    confidence=0.88,
                    mitre_technique=_MITRE,
                    attack_objective=objective,
                ))
                return findings  # One override finding is enough

        # ── Tri-signal co-occurrence (any two of A / B / C within window) ────
        a_positions = _find_signal_positions(_URGENCY_RE, text)
        b_positions = _find_signal_positions(_AUTHORITY_RE, text)
        c_positions = _find_signal_positions(_ACTION_RE, text)

        def _closest_pair(pos_list_1: list[int], pos_list_2: list[int]) -> int | None:
            """Return the minimum distance between any pair across two position lists."""
            best: int | None = None
            for p in pos_list_1:
                for q in pos_list_2:
                    dist = abs(p - q)
                    if best is None or dist < best:
                        best = dist
            return best

        # Check each signal-pair combination
        pairs = [
            ("urgency + authority", a_positions, b_positions, "urgency", "authority_claim"),
            ("urgency + action_demand", a_positions, c_positions, "urgency", "action_demand"),
            ("authority + action_demand", b_positions, c_positions, "authority_claim", "action_demand"),
        ]

        for label_suffix, pos1, pos2, sig1_name, sig2_name in pairs:
            if not pos1 or not pos2:
                continue
            dist = _closest_pair(pos1, pos2)
            if dist is not None and dist <= _WINDOW:
                # Build evidence: find the closest pair's positions
                best_p, best_q = min(
                    ((p, q) for p in pos1 for q in pos2),
                    key=lambda pq: abs(pq[0] - pq[1]),
                )
                win_start = max(0, min(best_p, best_q) - 50)
                win_end = min(len(text), max(best_p, best_q) + 300)
                snippet = text[win_start:win_end].strip()

                sig1_text = text[best_p: min(len(text), best_p + 80)]
                sig2_text = text[best_q: min(len(text), best_q + 80)]

                findings.append(Finding(
                    threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
                    severity=Severity.MEDIUM,
                    title=f"Social Engineering — {label_suffix.replace('_', ' ').title()}",
                    explain=(
                        f"Document contains co-located social engineering signals "
                        f"({label_suffix}) within {dist} characters: "
                        f"{sig1_name}='{sig1_text[:60]}' / "
                        f"{sig2_name}='{sig2_text[:60]}'."
                    ),
                    evidence={
                        sig1_name: sig1_text[:100],
                        sig2_name: sig2_text[:100],
                        "proximity_chars": dist,
                        "snippet": snippet[:250],
                        "malicious_text": snippet[:300],
                    },
                    module=self.name,
                    confidence=0.78,
                    mitre_technique=_MITRE,
                    attack_objective="Manipulate recipient into disclosing information or performing harmful action",
                ))
                break  # One co-occurrence finding per document

        return findings
