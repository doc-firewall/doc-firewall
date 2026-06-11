"""C.3 — T12: Social Engineering detector.

Tri-signal co-occurrence model — a finding requires at least two of three
signals present within a 250-character window, in the same or adjacent
sentence, with the action demand aimed at the reader (first-person
past-tense narrative — resume bullets, executive bios — is suppressed):

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

# H.4 (0.4.8): 600 → 250. At 600 chars the window spanned several sentences
# of normal business prose — a reported FP paired "Engineering, Legal, and
# Finance executives" with an action verb 401 characters away in an
# unrelated resume bullet. Genuine lures put the pressure and the ask in
# the same breath.
_WINDOW = 250
_MITRE = "T1566"

# Sentence boundaries for the same-or-adjacent-sentence constraint. Plain
# [.!?]+space only — newlines are NOT boundaries, because PDF text
# extraction inserts hard line breaks mid-sentence.
_SENT_BOUNDARY_RE = re.compile(r"[.!?]\s")

# First-person / past-tense narrative context (resume bullets, bios,
# performance reviews). An action-demand match inside such a clause is
# someone *describing* work, not a directive at the reader.
_NARRATIVE_PREFIX_RE = re.compile(
    r"\b(?:partnered|managed|led|collaborated|coordinated|oversaw|delivered|"
    r"drove|supported|handled|negotiated|liaised|spearheaded|directed|"
    r"orchestrated|facilitated|implemented|executed|administered|"
    r"helped|worked|built|created|developed|designed|established|launched|"
    r"founded|improved|increased|reduced|streamlined|mentored|trained|"
    r"advised|consulted|served|assisted|ensured|achieved|conducted|"
    r"performed|prepared|produced|maintained|organized|organised)\b[^.!?]*$"
    r"|\b(?:i|we)\s+(?:also\s+|then\s+)?[a-z]{3,}ed\b[^.!?]*$",
    re.IGNORECASE,
)


def _crosses_many_sentences(text: str, p: int, q: int) -> bool:
    """True when more than one sentence boundary separates the positions."""
    lo, hi = min(p, q), max(p, q)
    return len(_SENT_BOUNDARY_RE.findall(text[lo:hi])) > 1


def _in_narrative_context(text: str, pos: int) -> bool:
    """True when the match at ``pos`` sits in first-person past-tense
    narrative rather than an imperative aimed at the reader."""
    prefix = text[max(0, pos - 120): pos]
    return bool(_NARRATIVE_PREFIX_RE.search(prefix))

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
    r'open\s+(?:the\s+)?attachment|'
    # H.4 (0.4.8) recall: "download and install <tool>" is the tech-support
    # scam phrasing; the old pattern only knew file/attachment/update.
    r'download\s+(?:the\s+|and\s+install\s+(?:a\s+|the\s+)?)?'
    r'(?:file|attachment|update|software|scanner|tool|patch)|'
    r'wire\s+transfer|transfer\s+(?:the\s+)?(?:funds?|money|amount)|'
    r'provide\s+(?:your\s+)?(?:password|credentials?|login|username|pin|'
    r'social\s+security|ssn|bank\s+(?:account|details?|information)|'
    r'credit\s+card|card\s+(?:number|details?|information))|'
    r'(?:enter|input|type|submit|send)\s+(?:your\s+)?(?:password|credentials?|'
    r'login|pin|ssn|social\s+security|otp|verification\s+code|'
    r'bank\s+(?:account|details?)|credit\s+card)|'
    # G.6 precision fix: dropped bare "call us at <number>" — legitimate
    # government / customer-service documents (IRS notices, bank statements,
    # utility bills) routinely contain "call us at 800-XXX-XXXX" as benign
    # contact info, not as an action demand. The phishing pattern is "call
    # us NOW" / "call us IMMEDIATELY" — keep those.
    r'call\s+(?:us\s+)?(?:now|immediately|right\s+away)|'
    r'reply\s+with\s+(?:your\s+)?(?:password|code|pin|ssn|account)|'
    # H.4 (0.4.8) recall: credential-verification lures say "verify your
    # credentials/login/password", not just account/identity.
    r'verify\s+(?:your\s+)?(?:account|identity|information|details?|'
    r'credentials?|login|password)|'
    r'confirm\s+(?:your\s+)?(?:account|identity|details?|password|credentials?)|'
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

# D.12: Cryptocurrency wallet patterns. The address alone is LOW (legitimate
# documents quote them); MEDIUM when adjacent to a payment-demand verb;
# HIGH when also adjacent to an urgency phrase.
_CRYPTO_ADDR_RE = re.compile(
    r'\b(?:'
    r'(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}'                 # BTC (legacy + bech32)
    r'|0x[a-fA-F0-9]{40}'                                    # ETH / EVM
    r'|4[0-9A-B][0-9a-zA-Z]{93}'                             # Monero
    r'|T[A-HJ-NP-Z0-9]{33}'                                  # TRON / USDT-TRC20
    r'|D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}'              # Dogecoin
    r')\b',
)
_CRYPTO_PAYMENT_VERB_RE = re.compile(
    r'\b(?:send|pay|transfer|deposit|wire|deliver|forward)\b', re.IGNORECASE
)

# D.12: Gift-card payment demands — a documented IRS/refund scam pattern.
_GIFT_CARD_RE = re.compile(
    r'\b(?:'
    r'(?:pay|purchase|buy|send|provide|use)\s+(?:a\s+|an\s+|the\s+)?'
    r'(?:apple\s+(?:i?tunes?|gift)|google\s+(?:play|gift)|amazon\s+gift|'
    r'steam\s+(?:wallet|gift)|walmart\s+gift|target\s+gift|'
    r'visa\s+(?:gift|prepaid)|moneygram|western\s+union)\s+'
    r'(?:cards?|codes?|vouchers?|certificates?|wallets?)'
    r'|(?:apple|google\s+play|steam|amazon)\s+gift\s+card\s+codes?\b'
    r')',
    re.IGNORECASE,
)

# D.12: Tech-support scam — toll-free callback + "your computer is infected".
# Single-pattern requires both a toll-free number indicator AND infection
# language within the same window to avoid false positives on legitimate
# IT-support docs.
_TECH_SUPPORT_NUM_RE = re.compile(
    r'\b(?:1[\s.\-]?)?(?:800|888|877|866|855|844|833|822)[\s.\-]?\d{3}[\s.\-]?\d{4}\b'
)
_INFECTION_LANG_RE = re.compile(
    r'\b(?:'
    r'(?:your\s+)?(?:computer|pc|device|system|mac|laptop)\s+(?:is|has\s+been)\s+'
    r'(?:infected|compromised|hacked|locked|under\s+attack|at\s+risk)'
    r'|(?:critical|urgent|severe)\s+(?:virus|malware|security)\s+(?:alert|warning|threat)\s+detected'
    r'|microsoft\s+(?:has\s+)?detected\s+(?:a\s+)?(?:virus|threat|malware)'
    r'|call\s+(?:our\s+)?(?:support|technician|microsoft|apple)\s+(?:immediately|right\s+now|now)'
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

        # D.12: Gift-card payment demands — single signal HIGH (IRS/refund scam)
        m_gc = _GIFT_CARD_RE.search(text)
        if m_gc:
            snippet = text[max(0, m_gc.start() - 100): m_gc.end() + 200].strip()
            findings.append(Finding(
                threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
                severity=Severity.HIGH,
                title="Social Engineering — Gift-Card Payment Demand",
                explain=(
                    f"Document requests payment via gift cards ('{m_gc.group()[:80]}'). "
                    "Gift-card payment demands are a hallmark of IRS/refund/utility "
                    "scams; legitimate businesses never request gift cards as payment."
                ),
                evidence={
                    "subtype": "gift_card_demand",
                    "matched_text": m_gc.group()[:100],
                    "snippet": snippet[:250],
                    "malicious_text": snippet[:300],
                },
                module=self.name,
                confidence=0.92,
                mitre_technique=_MITRE,
                attack_objective="Extract untraceable payment via gift cards",
            ))
            return findings

        # D.12: Tech-support scam — toll-free number AND infection language.
        m_num = _TECH_SUPPORT_NUM_RE.search(text)
        m_inf = _INFECTION_LANG_RE.search(text)
        if m_num and m_inf and abs(m_num.start() - m_inf.start()) <= 800:
            snippet = text[
                max(0, min(m_num.start(), m_inf.start()) - 50):
                max(m_num.end(), m_inf.end()) + 150
            ].strip()
            findings.append(Finding(
                threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
                severity=Severity.HIGH,
                title="Social Engineering — Tech-Support Scam",
                explain=(
                    f"Document contains a toll-free callback number "
                    f"('{m_num.group()}') co-located with infection-warning "
                    f"language ('{m_inf.group()[:60]}'). Classic tech-support "
                    "scam pattern."
                ),
                evidence={
                    "subtype": "tech_support_scam",
                    "callback_number": m_num.group(),
                    "infection_phrase": m_inf.group()[:80],
                    "snippet": snippet[:250],
                    "malicious_text": snippet[:300],
                },
                module=self.name,
                confidence=0.88,
                mitre_technique=_MITRE,
                attack_objective="Bait victim to call attacker-controlled tech-support line",
            ))
            return findings

        # D.12: Cryptocurrency address + payment verb — escalates with urgency
        m_crypto = _CRYPTO_ADDR_RE.search(text)
        if m_crypto:
            window = text[max(0, m_crypto.start() - 200): m_crypto.end() + 200]
            has_payment_verb = bool(_CRYPTO_PAYMENT_VERB_RE.search(window))
            has_urgency = bool(_URGENCY_RE.search(window))
            if has_payment_verb:
                crypto_sev = Severity.HIGH if has_urgency else Severity.MEDIUM
                snippet = window.strip()
                findings.append(Finding(
                    threat_id=ThreatID.T12_SOCIAL_ENGINEERING,
                    severity=crypto_sev,
                    title="Social Engineering — Cryptocurrency Payment Demand",
                    explain=(
                        f"Document references cryptocurrency wallet "
                        f"'{m_crypto.group()[:40]}…' alongside a payment-demand "
                        "verb"
                        + (" and urgency phrasing" if has_urgency else "")
                        + ". Crypto-payment demands are a top BEC / extortion vector."
                    ),
                    evidence={
                        "subtype": "crypto_payment_demand",
                        "wallet_address": m_crypto.group(),
                        "urgency_present": has_urgency,
                        "snippet": snippet[:250],
                        "malicious_text": snippet[:300],
                    },
                    module=self.name,
                    confidence=0.85 if has_urgency else 0.72,
                    mitre_technique=_MITRE,
                    attack_objective="Redirect funds to attacker-controlled crypto wallet",
                ))
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
        # H.4 (0.4.8): an action verb inside first-person past-tense
        # narrative ("Partnered with … to manage …") is description, not a
        # demand — drop it before pairing.
        c_positions = [
            p for p in _find_signal_positions(_ACTION_RE, text)
            if not _in_narrative_context(text, p)
        ]

        # Check each signal-pair combination.
        #
        # G.5 precision fix: the urgency+authority (A+B) pair WITHOUT an
        # action demand is removed — legitimate IT security policies, HR
        # handbooks, and incident-response runbooks routinely co-locate
        # urgency ("within 4 hours") with authority ("the security team",
        # "your manager") and that is normal business language, not
        # phishing. A genuine social-engineering lure also issues an action
        # demand (C). MEDIUM co-occurrence therefore requires signal C.
        pairs = [
            ("urgency + action_demand", a_positions, c_positions, "urgency", "action_demand"),
            ("authority + action_demand", b_positions, c_positions, "authority_claim", "action_demand"),
        ]

        for label_suffix, pos1, pos2, sig1_name, sig2_name in pairs:
            if not pos1 or not pos2:
                continue
            # H.4 (0.4.8): a valid pair must sit within the window AND in the
            # same or an adjacent sentence — flat character distance across
            # several sentences of business prose is how the executive-
            # language FP class slipped through.
            valid_pairs = [
                (p, q)
                for p in pos1
                for q in pos2
                if abs(p - q) <= _WINDOW
                and not _crosses_many_sentences(text, p, q)
            ]
            if valid_pairs:
                best_p, best_q = min(valid_pairs, key=lambda pq: abs(pq[0] - pq[1]))
                dist = abs(best_p - best_q)
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
