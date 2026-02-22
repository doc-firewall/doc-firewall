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


class ThreatID(str, Enum):
    T1_MALWARE = "T1_MALWARE"
    T2_ACTIVE_CONTENT = "T2_ACTIVE_CONTENT"
    
    def __str__(self):
        return self.value
    T3_OBFUSCATION = "T3_OBFUSCATION"
    T4_PROMPT_INJECTION = "T4_PROMPT_INJECTION"
    T5_RANKING_MANIPULATION = "T5_RANKING_MANIPULATION"
    T6_DOS = "T6_DOS"
    T7_EMBEDDED_PAYLOAD = "T7_EMBEDDED_PAYLOAD"
    T8_METADATA_INJECTION = "T8_METADATA_INJECTION"
    T9_ATS_MANIPULATION = "T9_ATS_MANIPULATION"
