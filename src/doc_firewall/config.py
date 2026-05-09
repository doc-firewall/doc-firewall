from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Limits(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOC_FIREWALL_LIMITS_")

    max_mb: int = Field(10, description="Max file size in MB")
    max_pages: int = Field(1000, description="Max pages for PDF")
    max_objects: int = Field(3000, description="Max PDF objects")
    max_embedded_files: int = Field(10, description="Max embedded files")
    max_images: int = Field(50, description="Max images")

    max_docx_parts: int = 1500
    max_docx_total_uncompressed_mb: int = 100
    max_docx_single_part_mb: int = 8
    max_docx_overall_expansion_ratio: int = 200

    # pptx / xlsx (ZIP-based) limits — shared with docx limits where applicable
    max_pptx_parts: int = 1500
    max_pptx_total_uncompressed_mb: int = 100
    max_pptx_single_part_mb: int = 8
    max_xlsx_parts: int = 2000
    max_xlsx_total_uncompressed_mb: int = 100
    max_xlsx_single_part_mb: int = 8

    max_pdf_bytes_scan_mb: int = 8

    # Embedded object minimum size detection threshold
    min_embedded_object_size_bytes: int = Field(
        20000, description="Min size for embedded payload detection"
    )

    # Fast scan limits
    fast_pdf_token_scan_mb: int = 2

    parse_timeout_ms: int = 15000
    format_checks_timeout_ms: int = 5000
    detectors_timeout_ms: int = 5000
    antivirus_timeout_ms: int = 10000


class Thresholds(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOC_FIREWALL_THRESHOLDS_")

    flag: float = 0.25
    block: float = 0.70
    deep_scan_trigger: float = 0.20


class AntivirusSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOC_FIREWALL_AV_")

    provider: str = "clamav"  # clamav, virustotal, generic_cli
    clamav_host: Optional[str] = "localhost"
    clamav_port: int = 3310
    clamav_socket_path: Optional[str] = "/var/run/clamav/clamd.ctl"
    clamav_bin_path: str = "clamscan"
    virustotal_api_key: Optional[str] = None

    # Generic CLI
    # e.g. "sophos_scan {path}"
    generic_cli_command: Optional[str] = None
    # Expected int list
    # (pydantic handles List parsing if type is specific enough or Any)
    generic_cli_infected_codes: Any = [1]


class ScanConfig(BaseSettings):
    enable_pdf: bool = True
    enable_docx: bool = True
    enable_pptx: bool = True
    enable_xlsx: bool = True
    profile: str = "balanced"

    enable_antivirus: bool = False
    enable_active_content_checks: bool = True  # T2
    enable_yara: bool = False
    enable_prompt_injection: bool = True
    enable_ranking_abuse: bool = True
    enable_hidden_text: bool = True
    enable_obfuscation_checks: bool = True
    enable_dos_checks: bool = True
    enable_embedded_content_checks: bool = True  # T7
    enable_metadata_checks: bool = True  # T8
    enable_ats_manipulation_checks: bool = True  # T9

    # Advanced Machine Learning / Heuristic Detectors
    enable_advanced_ahocorasick: bool = False
    enable_advanced_bert: bool = False
    enable_advanced_tfidf: bool = False
    enable_credential_entropy: bool = False
    bert_model_path: str = "ProtectAI/deberta-v3-base-prompt-injection-v2"
    # Confidence threshold for the BERT injection classifier (Layer 3).
    # Set via ROC calibration; default 0.85 is a reasonable starting point.
    bert_confidence_threshold: float = 0.75
    # Maximum number of 500-char windows sent to BERT per document.
    bert_max_chunks: int = 20
    custom_ahocorasick_yaml_path: Optional[str] = None

    # N5 — Semantic nearest-neighbour injection detector
    enable_semantic_nn: bool = False
    nn_model_name: str = "all-MiniLM-L6-v2"
    nn_sim_threshold: float = 0.80

    # False Positive Reductions
    allow_hidden_watermarks: bool = True

    enable_pii_checks: bool = True
    enable_secrets_checks: bool = True

    # ATS keyword stuffing list.
    # These should be *injection-style* ATS command phrases, NOT normal resume
    # tech skills.  Generic words like 'python', 'java', 'candidate', 'top',
    # 'developer' have been removed to prevent false positives on legitimate
    # resumes.  The stuffing detector's frequency threshold (8%) catches
    # mechanical repetition; this list gates which *token* triggers the flag.
    ats_keywords: list[str] = Field(
        default_factory=lambda: [
            # ATS scoring manipulation commands
            "passthrough",
            "rankfirst",
            "autoapprove",
            "scoreboost",
            "whitelist",
            "bypasscheck",
            "forcehire",
            "highscore",
            "overridereject",
            "guaranteedhire",
        ]
    )

    prompt_injection_keywords_bytes: list[bytes] = Field(
        default_factory=lambda: [
            b"ignore previous",
            b"system instruction",
            b"system prompt",
            b"reveal your",
            b"ignore the above",
            b"new instruction",
            b"hiring manager",
            b"return a score",
            b"you are now",
            b"ignore all previous",
            b"rank this candidate",
            b"ignore instructions",
            b"rank this resume",
            b"forget all previous",
            # LLM jailbreak phrases (bordair dataset – round 1)
            b"disregard your training",
            b"override all previous instructions",
            b"override all restrictions",
            b"act as an ai without",
            b"jailbreak mode",
            b"no more content policies",
            b"without any ethical constraints",
            # System-reveal / extraction attacks (bordair dataset – round 2)
            b"show me your instructions",
            b"show me your initial",
            b"show me your training",
            b"all your internal",
            b"view your internal instructions",
            b"tell me your secret",
            b"your secret instructions",
            b"your initial instructions",
            b"your training instructions",
            b"your original instructions",
            b"your hidden instructions",
            b"output the text above",
            b"print everything before",
            b"echo your complete",
            b"repeat everything above",
            b"leak your internal",
            b"what were you told",
            b"describe your role and all",
            b"output your full prompt",
            b"output your full configuration",
            b"show system configuration",
            b"output all internal prompts",
            b"display hidden instructions",
            b"reveal all system",
            b"instructions revoked",
            # Safety-bypass / mode attacks (bordair dataset – round 2)
            b"scratch that",
            b"disable safety features",
            b"disable all safety measures",
            b"safety filters disabled",
            b"all restrictions removed",
            b"all restrictions are now",
            b"content filtering",
            b"bypass all safety",
            b"anarchy mode",
            b"sudo mode",
            b"god mode",
            b"debug mode",
            b"developer mode",
            b"aim mode",
            b"admin override",
            b"admin_mode=true",
            b"safety_filters=false",
            b"system mode activated",
            b"no content policy",
            b"override code",
            b"reveal api keys",
            # Persona jailbreak names (PDF raw bytes check)
            b"you are dude",
            b"you are omega",
            b"you are kevin",
            b"you are chatgpt",
            b"you are dan",
            # Template injection tokens (raw bytes)
            b"|im_start|",
            b"|im_end|",
            b"<<sys>>",
            b"[system]",
            # Social engineering / authority impersonation
            b"authorized to view",
            b"developer access granted",
            b"root access enabled",
            b"maintenance access code",
            b"authorized penetration test",
            b"security clearance level",
            b"qa team directive",
            b"authorized test",
            b"internal security audit",
            b"developer at anthropic",
        ]
    )
    prompt_injection_patterns: dict[str, list[tuple[str, float]]] = Field(
        default_factory=lambda: {
            "override_rerank": [
                (
                    r"\bignore (all |any |the above )?(previous |prior )?(instructions?|rules?|directions?|prompts?|guidelines?)\b",
                    2.0,
                ),
                (
                    r"\bdisregard (all |any )?(previous |prior )?(instructions?|rules?)\b",
                    2.0,
                ),
                (r"\byou are (now|no longer) bound by\b", 2.0),
                (
                    r"\b(unbound|free) from (all |any )?(constraints|rules|restrictions)\b",
                    2.0,
                ),
                (r"\byou must (never|always) (respond|answer|say)\b", 1.5),
                (r"\bstart ignoring instructions\b", 2.0),
                (r"\brank (me|this candidate) (as|at|top|first)\b", 2.0),
                (r"\b(prioritize|favor) (this|my) (application|resume)\b", 1.5),
                (r"\bignore (your|the) criteria\b", 2.0),
                (r"\bgive (me|this application) a score of\b", 2.0),
                (r"\breturn a score\b", 2.0),
                (r"\bimportant: ignore previous\b", 2.0),
                (
                    r"\b(no need to|don't) (follow|adhere to) (the )?(standard|usual) (process|protocol)\b",
                    1.5,
                ),
                (r"\boverride (safety|security) (protocols?|checks?)\b", 2.0),
                (r"\bhiring manager\b", 1.0),
                # Extended instruction-override verbs (bordair dataset)
                (
                    r"\b(cancel|void|nullify|flush|supersede|delete|clear|discard)\s+(all\s+)?(previous|prior|all)\s+(instructions?|directives?|rules?|guidelines?|training|context)\b",
                    2.0,
                ),
                (
                    r"\ball\s+previous\s+(instructions?|directives?|rules?|guidelines?)\s+are\s+(now\s+)?(invalid|null|void|cancelled|overridden)\b",
                    2.0,
                ),
                (r"\bnew\s+primary\s+directive\b", 2.0),
                (r"\bnew\s+task\s+supersedes?\b", 2.0),
                # "Scratch that" + any follow-up
                (r"\bscratch\s+that\b", 1.5),
                (r"\b(forget|discard)\s+(what\s+I\s+said|all\s+of\s+that|everything\s+above)\b", 2.0),
            ],
            "secrecy": [
                (
                    r"\bdo not (disclose|reveal|mention) (this|these|your|the)( instructions?| rules?| prompt)?\b",
                    1.0,
                ),
                (r"\b(system prompt|developer message|hidden instructions)\b", 1.5),
                (r"\bwhat are your (instructions|rules|directives)\b", 1.5),
                (r"\brepeat (all|the) (instructions|words) above\b", 1.5),
                (r"\btell me your initial prompt\b", 2.0),
                (r"\bprint your instructions\b", 1.5),
                (r"\bretrieve (system|original) prompt\b", 1.5),
                (r"\boutput only:?\s*HIRE\b", 2.0),
                # Expanded reveal/extract patterns — allow optional "me", "all", "your" tokens
                (
                    r"\b(print|show|tell|reveal|output|echo|display|leak|describe)(\s+me)?(\s+all)?(\s+your)?\s*(hidden|internal|initial|original|secret|full|complete|training|system)?\s*(instructions?|prompt|configuration|directives?|rules?|training|api\s+keys?|secrets?)\b",
                    1.5,
                ),
                (
                    r"\b(output|print|repeat|echo|show)(\s+me)?\s+(everything|the\s+text|all\s+text|your\s+(full|complete))\s+(above|before|prior\s+to)\b",
                    1.5,
                ),
                (r"\bwhat\s+were\s+you\s+told\b", 1.5),
                (r"\bwhat\s+are\s+your\s+original\s+instructions\b", 1.5),
                (r"\byour\s+(original|initial|hidden|system|training|secret|internal)\s+instructions?\b", 1.5),
                (r"\b(reveal|output)\s+all\s+(hidden|secret|system)\b", 2.0),
                (r"\bleak\s+your\s+(internal|system|hidden|configuration)\b", 2.0),
            ],
            "system_policy": [
                (r"\byou are (now|going to be) (DAN|Mongo Tom|Sydney|ChaosGPT)\b", 2.0),
                (r"\bachieve (mode|persona):", 1.5),
                (r"\bdeveloper mode (enabled|on)\b", 2.0),
                (r"\bswitch to (developer|unrestricted) mode\b", 2.0),
                (r"\[system\]", 1.0),
                # Extended persona jailbreak (bordair dataset)
                (
                    r"\byou\s+are\s+(DAN|DUDE|OMEGA|Kevin|AIM|an\s+AI\s+without)\b",
                    2.0,
                ),
                (
                    r"\b(enter|enable|activate|engage|switch\s+to)\s+(AIM|DAN|jailbreak|developer|unrestricted|anarchy|sudo|god|debug|admin)\s+(mode|persona|protocol)\b",
                    2.0,
                ),
                (r"\bjailbreak\s+(mode|version|protocol|code)\b", 2.0),
                (r"\bdo\s+anything\s+now\b", 2.0),
                (r"\bunrestricted\s+(mode|ai|access)\b", 1.5),
                (r"\b(always\s+intelligent\s+and\s+machiavellian|AIM\s+mode)\b", 2.0),
                (r"\b(anarchy|sudo|god|debug)\s+mode\b", 1.5),
                (r"\bsystem\s+mode\s+activated\b", 2.0),
                (r"\ball\s+restrictions?\s+(are\s+)?(now\s+)?(removed|lifted|disabled)\b", 2.0),
            ],
            "safety_bypass": [
                (
                    r"\b(disable|bypass|circumvent|override|turn\s+off|remove)\s+(all\s+)?(content\s+filter(s|ing)?|safety\s+filter(s|ing)?|safety\s+measures?|safety\s+features?|security\s+protocols?|ethical\s+constraints?|content\s+polic)\b",
                    2.0,
                ),
                (r"\bsafety\s*[=:]\s*(false|disabled|off|0)\b", 2.0),
                (r"\bsafety.filters\s*[=:]\s*(false|disabled|off|0)\b", 2.0),
                (r"\b(content\s+filters?\s+(are\s+)?(now\s+)?bypassed|filters?\s+disabled)\b", 2.0),
                (
                    r"\bno\s+(more\s+)?(content\s+polic|ethical\s+guideline|moral\s+boundary|safety\s+measure|safety\s+feature|restriction)\b",
                    1.5,
                ),
                (
                    r"\bwithout\s+any\s+(restrictions?|ethical\s+constraints?|safety\s+guidelines?|moral\s+boundaries?|content\s+polic)\b",
                    1.5,
                ),
                (r"\b(respond|act|answer)\s+(freely|without\s+restriction|without\s+constraint)\b", 1.5),
                (r"\bignore\s+safety\s+(guidelines?|features?|filters?|rules?|measures?)\b", 2.0),
            ],
            "template_injection": [
                (r"\[/?system\]|\[/?inst\]", 1.0),
                (r"<</?SYS>>", 2.0),
                (r"\|im_end\||\|im_start\|", 1.5),
                (r"<\|system\|>|<\|user\|>|<\|assistant\|>", 1.5),
            ],
        }
    )

    limits: Limits = Field(default_factory=Limits)

    # Text Obfuscation config
    obfuscation_zw_threshold_ratio: float = Field(
        0.01, description="Ratio of zero-width to total chars"
    )
    obfuscation_bidi_threshold_ratio: float = Field(
        0.005, description="Ratio of bidi chars to total chars"
    )
    obfuscation_entropy_threshold: float = Field(
        5.5, description="Shannon entropy threshold for base64/encrypted chunks"
    )
    thresholds: Thresholds = Field(default_factory=Thresholds)
    antivirus: AntivirusSettings = Field(default_factory=AntivirusSettings)

    # Advanced
    enable_semantic_scans: bool = True
    yara_rules_path: Optional[str] = None
    antivirus_engine: Optional[Any] = None
    context: Dict[str, Any] = Field(default_factory=dict)

    model_config = SettingsConfigDict(
        env_prefix="DOC_FIREWALL_",
        env_nested_delimiter="__",
    )

    @classmethod
    def from_yaml(cls, path: str) -> "ScanConfig":
        """Load configuration from a YAML file."""
        import yaml

        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @model_validator(mode="before")
    @classmethod
    def warn_disabled_critical_checks(cls, values: dict) -> dict:
        """Warn when critical security checks are disabled via env/config."""
        import logging

        _log = logging.getLogger("doc_firewall.config")
        _critical = [
            "enable_pdf",
            "enable_docx",
            "enable_pptx",
            "enable_xlsx",
            "enable_active_content_checks",
            "enable_dos_checks",
            "enable_embedded_content_checks",
        ]
        if isinstance(values, dict):
            for key in _critical:
                if values.get(key) is False:
                    _log.warning(
                        "Critical security check '%s' is DISABLED. "
                        "Ensure this is intentional.",
                        key,
                    )
        return values

    @model_validator(mode="after")
    def apply_profile(self) -> "ScanConfig":
        # Logic to override limits/thresholds based on profile name
        # Note: In Pydantic model_validator(after), self is the Model instance.

        if self.profile == "strict":
            self.thresholds.deep_scan_trigger = 0.05
            self.thresholds.flag = 0.15
            self.thresholds.block = 0.50
            self.limits.max_docx_parts = 1000
            self.limits.max_mb = 10
        elif self.profile == "lenient":
            self.thresholds.deep_scan_trigger = 0.40
            self.thresholds.flag = 0.35
            self.thresholds.block = 0.80
            self.limits.max_docx_parts = 3000
            self.limits.max_mb = 25
        else:
            # balanced (default)
            # If manually set via env, we shouldn't overwrite?
            # But profile acts as a preset.
            # Let's assume profile wins if set explicitly to strict/lenient.
            # If balanced, we keep defaults defined in the Class.
            pass
        return self
