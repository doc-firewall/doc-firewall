from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerdictClass(str, Enum):
    """Class of a finding's contribution to the overall scan verdict.

    The scanner verdict is derived from finding classes, NOT from a
    probabilistic score threshold. This makes BLOCK decisions explainable:
    a document is only BLOCKed when at least one finding carries
    *definitive* evidence of malicious intent (a YARA hit, a javascript:
    URI, etc.), never from an accumulation of weak heuristics.

      BLOCK   — definitive: any single finding of this class forces
                verdict = BLOCK. Examples: YARA signature match, EICAR
                test file, javascript:/data:/vbscript: URI, /JavaScript
                + /OpenAction co-occurrence, embedded PE in object stream,
                JBIG2Decode + oversized dimensions (CVE-2021-30860).

      REVIEW  — heuristic / suggestive: contributes to risk_score but
                only escalates verdict to FLAG, never BLOCK. Examples:
                ToUnicode CMap remap ratios, indirect-injection co-
                occurrence, PII presence, social-engineering tri-signal,
                most prompt-injection ML hits.

      INFO    — recorded for audit but never affects verdict or risk
                score. Examples: 'PDF contains 2 incremental update
                layers' (true of any edited PDF), 'document has author
                metadata'.
    """
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    INFO = "INFO"


class ThreatID(str, Enum):
    T1_MALWARE = "T1_MALWARE"
    T2_ACTIVE_CONTENT = "T2_ACTIVE_CONTENT"

    def __str__(self) -> str:
        return self.value

    T3_OBFUSCATION = "T3_OBFUSCATION"
    T4_PROMPT_INJECTION = "T4_PROMPT_INJECTION"
    T5_RANKING_MANIPULATION = "T5_RANKING_MANIPULATION"
    T6_DOS = "T6_DOS"
    T7_EMBEDDED_PAYLOAD = "T7_EMBEDDED_PAYLOAD"
    T8_METADATA_INJECTION = "T8_METADATA_INJECTION"
    T9_ATS_MANIPULATION = "T9_ATS_MANIPULATION"
    T10_INDIRECT_INJECTION = "T10_INDIRECT_INJECTION"
    T11_RAG_POISONING = "T11_RAG_POISONING"
    T12_SOCIAL_ENGINEERING = "T12_SOCIAL_ENGINEERING"
