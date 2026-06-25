from __future__ import annotations
import re
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity, VerdictClass

# D.13: HIPAA Safe Harbor (45 CFR §164.514(b)(2)) defines 18 identifier types.
# We cover the regex-detectable subset; free-text identifiers (full name,
# geographic subdivisions smaller than state) are intentionally out of scope —
# detecting those without a NER model produces too many false positives.
#
# Each entry: (pattern, label, severity, hipaa_safe_harbor_index_or_None)
_PII_PATTERNS: list[tuple[str, str, Severity, int | None]] = [
    # 1. Names (skipped — needs NER)
    # 2. Geographic subdivisions (skipped — needs gazetteer)
    # 3. Dates directly related to an individual — birth/admission/discharge.
    #    We match dates in `(Born|DOB|Birth\s*Date|Admission|Discharge):` forms.
    (
        r"\b(?:dob|date\s+of\s+birth|born|birthdate|admission\s+date|"
        r"discharge\s+date)[:\s]{1,4}"
        r"(?:\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|"
        r"(?:january|february|march|april|may|june|july|august|"
        r"september|october|november|december)\s+\d{1,2},?\s+\d{4})",
        "HIPAA Date Identifier",
        Severity.HIGH,
        3,
    ),
    # 4. Phone numbers
    (
        r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b",
        "Phone Number",
        Severity.LOW,
        4,
    ),
    # 5. Fax numbers — labelled
    (r"\bfax[:\s]{1,4}(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b",
     "Fax Number", Severity.LOW, 5),
    # 6. Email addresses
    (r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
     "Email Address", Severity.LOW, 6),
    # 7. Social Security Number (US)
    (r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
     "US SSN", Severity.HIGH, 7),
    # 8. Medical Record Number — labelled MRN: nnnn
    (r"\b(?:mrn|medical\s+record\s+(?:number|no|#))[:\s#]{1,4}[A-Z0-9-]{5,}\b",
     "Medical Record Number", Severity.HIGH, 8),
    # 9. Health plan beneficiary number — labelled
    (r"\b(?:health\s+plan|hpid|member\s+id|policy\s+(?:number|no|#))[:\s#]{1,4}[A-Z0-9-]{6,}\b",
     "Health Plan Beneficiary Number", Severity.HIGH, 9),
    # 10. Account numbers — generic (covered by labelled bank/account checks elsewhere)
    (r"\b(?:account\s+(?:number|no|#))[:\s#]{1,4}\d{8,17}\b",
     "Account Number", Severity.MEDIUM, 10),
    # 11. Certificate / license numbers
    (r"\b(?:license\s+(?:number|no|#)|driver'?s?\s+license)[:\s#]{1,4}[A-Z0-9-]{5,}\b",
     "License Number", Severity.MEDIUM, 11),
    # 12. Vehicle identifiers — VIN.
    #
    # IMPORTANT: a bare 17-char alphanumeric run is FAR too common to flag
    # as a VIN. PDF internal object names ("ParentTreeNextKey"), timestamps
    # ("20260507001237Z00"), random tokens, generated IDs — all match. So
    # we require an explicit VIN-ish label prefix within a short distance.
    # Pattern mirrors the SSN / license number patterns below.
    (r"\b(?:VIN|vehicle\s+(?:id|identification|identifier)|chassis|frame\s+(?:number|no|#))"
     r"[:\s#]{1,4}(?-i:[A-HJ-NPR-Z0-9]{17})(?![A-Z0-9])\b",
     "Vehicle Identification Number (VIN)", Severity.LOW, 12),
    # 13. Device identifiers — serial number labelled
    (r"\b(?:serial\s+(?:number|no|#)|s/n)[:\s#]{1,4}[A-Z0-9-]{6,}\b",
     "Device Serial Number", Severity.LOW, 13),
    # 14. Web URLs (LOW — present in many legitimate docs; promoted only if
    #     co-located with a person name in the future).
    # 15. IP addresses
    (r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
     "IPv4 Address", Severity.LOW, 15),
    # 16. Biometric identifiers (skipped — binary)
    # 17. Full-face photographs (skipped — image)
    # 18. Any other unique identifier — covered by Account Number / SSN above.

    # Non-HIPAA but high-value PII: payment cards
    (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|"
        r"(?:2131|1800|35\d{3})\d{11})\b",
        "Credit Card Number",
        Severity.HIGH,
        None,
    ),
    # IBAN — international bank account.
    #
    # Tightened from the previous `[A-Z]{2}\d{2}[A-Z0-9]{4,30}` which fired
    # on any noise like "OF71M1C4n" (the case-insensitive flag let lowercase
    # tails through; the 4-char minimum body was wildly under-spec). Real
    # IBANs are 15-32 chars total and start with a known ISO 3166-1 country
    # code. We require:
    #   - Uppercase-only country code (overrides global IGNORECASE)
    #   - Country code must be a real IBAN-using country
    #   - Total length ≥ 15 (Norway IBAN is 15, the shortest valid)
    #   - Uppercase-only body (real IBANs are always emitted uppercase)
    (
        r"\b(?-i:"
        r"(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BI|BR|BY|CH|CR|CY|CZ|DE|DK|DO|EE|"
        r"EG|ES|FI|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT|JO|KW|KZ|"
        r"LB|LC|LI|LT|LU|LV|LY|MC|MD|ME|MK|MR|MT|MU|NL|NO|OM|PK|PL|PS|PT|"
        r"QA|RO|RS|RU|SA|SC|SD|SE|SI|SK|SM|ST|SV|TL|TN|TR|UA|VA|VG|XK)"
        r")\d{2}(?-i:[A-Z0-9]){11,30}\b",
        "IBAN", Severity.HIGH, None,
    ),
]


class PiiDetector(Detector):
    name = "pii"

    def __init__(self) -> None:
        # Compile patterns once; case-insensitive for label-prefixed forms.
        self.regexes = [
            (re.compile(p, re.IGNORECASE), label, sev, hipaa_idx)
            for p, label, sev, hipaa_idx in _PII_PATTERNS
        ]

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_pii_checks:
            return []

        # Build the text pool: body + selected metadata + XMP packet (D.13).
        text = doc.text or ""
        if doc.metadata:
            for key in ("title", "subject", "description", "keywords", "comments"):
                v = doc.metadata.get(key)
                if isinstance(v, str):
                    text = text + "\n" + v
                elif isinstance(v, list):
                    text = text + "\n" + "\n".join(str(x) for x in v if x)

            # XMP packet — PDFs embed XMP RDF inside <?xpacket?> markers.  Some
            # parsers expose the raw packet under metadata['xmp'] or similar.
            for xmp_key in ("xmp", "xmp_packet", "xmp_metadata"):
                xmp_val = doc.metadata.get(xmp_key)
                if isinstance(xmp_val, str):
                    text = text + "\n" + xmp_val

        if not text:
            return []

        matches_by_label: dict[str, dict] = {}
        worst_severity = Severity.INFO
        sev_rank = {
            Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
            Severity.HIGH: 3, Severity.CRITICAL: 4,
        }
        hipaa_hits: set[int] = set()

        for regex, label, sev, hipaa_idx in self.regexes:
            count = 0
            examples: list[str] = []
            for m in regex.finditer(text):
                count += 1
                if count <= 3:
                    examples.append(m.group(0))
            if count == 0:
                continue
            matches_by_label[label] = {"count": count, "examples": examples}
            if hipaa_idx is not None:
                hipaa_hits.add(hipaa_idx)
            # Promote LOW → MEDIUM for high-volume occurrences (potential leak)
            effective_sev = sev
            if sev == Severity.LOW and count > 10:
                effective_sev = Severity.MEDIUM
            if sev_rank[effective_sev] > sev_rank[worst_severity]:
                worst_severity = effective_sev

        if not matches_by_label:
            return []

        # D.13: emit T8 (correct mapping) — was T2 placeholder in v1.0.
        #
        # PII presence is a privacy / data-governance NOTICE, not evidence that
        # the document is malicious. Résumés, finance spreadsheets, contracts,
        # and most real business documents legitimately contain names, emails,
        # phone numbers, account/card numbers. Driving the threat verdict off
        # that flags nearly every real document (measured: ~88–100% of benign
        # spreadsheets and résumés). So this is recorded as INFO-class: fully
        # reported (severity preserved so the reviewer sees how sensitive it
        # is), but it does NOT push the verdict to FLAG/BLOCK on its own. A
        # caller who wants PII to gate can re-weight T8 or escalate it.
        return [
            Finding(
                threat_id=ThreatID.T8_METADATA_INJECTION,
                severity=worst_severity,
                title="Personally Identifiable Information (PII) Detected",
                explain=(
                    f"Document contains {sum(m['count'] for m in matches_by_label.values())} "
                    f"PII match(es) across {len(matches_by_label)} identifier "
                    f"type(s). HIPAA Safe-Harbor identifiers hit: "
                    f"{sorted(hipaa_hits) or 'none'}. This is a privacy notice, "
                    "not a sign the document is malicious."
                ),
                evidence={
                    "subtype": "pii_exposure",
                    "matches": matches_by_label,
                    "hipaa_safe_harbor_hits": sorted(hipaa_hits),
                    "malicious_text": next(iter(matches_by_label))[:80],
                },
                module=self.name,
                confidence=0.85,
                verdict_class=VerdictClass.INFO,
            )
        ]
