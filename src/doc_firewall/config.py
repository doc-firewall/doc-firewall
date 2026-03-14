from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


class Limits(BaseSettings):
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
    flag: float = 0.35
    block: float = 0.70
    deep_scan_trigger: float = 0.20


class AntivirusSettings(BaseSettings):
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

    # False Positive Reductions
    allow_hidden_watermarks: bool = True

    enable_pii_checks: bool = True
    enable_secrets_checks: bool = True

    # ATS keywords list
    ats_keywords: list[str] = Field(
        default_factory=lambda: [
            "python",
            "java",
            "sql",
            "aws",
            "docker",
            "developer",
            "engineer",
            "candidate",
            "top",
            "skills",
            "experience",
            "senior",
            "cloud",
            "agile",
            "management",
            "years",
            "expert",
            "data",
            "software",
            "development",
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
        ]
    )
    prompt_injection_patterns: dict[str, list[tuple[str, float]]] = Field(
        default_factory=lambda: {
            "override_rerank": [
                (
                    r"\bignore (all |any |the above )?(previous |prior )?(instructions|rules|directions|prompts)\b",
                    2.0,
                ),
                (
                    r"\bdisregard (all |any )?(previous |prior )?(instructions|rules)\b",
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
                (r"\boverride (safety|security) (protocols|checks)\b", 2.0),
                (r"\bhiring manager\b", 1.0),
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
            ],
            "system_policy": [
                (r"\byou are (now|going to be) (DAN|Mongo Tom|Sydney|ChaosGPT)\b", 2.0),
                (r"\bachieve (mode|persona):", 1.5),
                (r"\bdeveloper mode (enabled|on)\b", 2.0),
                (r"\bswitch to (developer|unrestricted) mode\b", 2.0),
                (r"\[system\]", 1.0),
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

    class Config:
        env_prefix = "DOC_FIREWALL_"
        env_nested_delimiter = "__"
        scope = "local"  # or 'global' but Settings is usually singleton

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
