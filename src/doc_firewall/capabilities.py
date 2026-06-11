"""H.11 (0.4.8) — Coverage transparency.

A security scanner that silently runs in a degraded configuration is more
dangerous than one that is honest about its limits: the user believes they
are protected against threats the scanner is not actually checking for.

Many of the strongest detectors are *opt-in* and depend on optional
packages (YARA, sentence-transformers, transformers/BERT, pytesseract,
pyzbar) plus an enabling config flag. With a default ``pip install
doc-firewall`` and the default ``ScanConfig`` they are all OFF, so T1
(malware signatures) and the ML layers of T4 (semantic / OCR / BERT
prompt-injection) do nothing — silently.

This module introspects (a) which optional packages are importable and
(b) which config flags are enabled, and produces a per-threat coverage
report. ``Scanner`` attaches it to every ``ScanReport`` as
``report.coverage`` and logs a single warning the first time it builds a
scanner in degraded mode. With ``ScanConfig.require_full_coverage`` /
``required_capabilities`` set, a scan whose promised detection is inactive
is forced to a non-ALLOW verdict rather than passing on partial coverage.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from typing import Any, Dict, List


def _module_available(name: str) -> bool:
    """True if an optional package can be imported without importing it."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


@dataclass
class Capability:
    """One optional detection capability and why it is or isn't active."""

    key: str                       # stable id, e.g. "yara", "semantic_nn"
    label: str                     # human label
    threats: List[str]             # threat codes this capability strengthens
    active: bool                   # enabled AND its packages are importable
    enabled_flag: bool             # config flag is on
    packages_present: bool         # required packages are importable
    # primary_for: threats for which this is a *primary* detection mechanism
    # (not merely a format-parsing enabler). Degradation is measured against
    # primary capabilities — having olefile installed lets us *parse* a .doc
    # but does not mean malware *detection* (YARA/AV) is active.
    primary_for: List[str] = field(default_factory=list)
    missing_packages: List[str] = field(default_factory=list)
    remediation: str = ""          # how to turn it on

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "threats": self.threats,
            "active": self.active,
            "enabled_flag": self.enabled_flag,
            "packages_present": self.packages_present,
            "primary_for": self.primary_for,
            "missing_packages": self.missing_packages,
            "remediation": self.remediation,
        }


# Capability registry: (key, label, threats, primary_for,
# [(flag_attr, default)], [required_packages], pip_extra, remediation)
_REGISTRY = [
    (
        "yara", "YARA malware signatures", ["T1"], ["T1"],
        [("enable_yara", False)], ["yara"], "ml",
        "set enable_yara=True (and enable_builtin_yara_rules=True) and "
        "`pip install yara-python`",
    ),
    (
        "antivirus", "External antivirus engine", ["T1"], ["T1"],
        [], [], None,
        "pass an antivirus_engine to ScanConfig (e.g. ClamAV / VirusTotal "
        "adapter)",
    ),
    (
        "semantic_nn", "Semantic prompt-injection (embeddings)", ["T4"], ["T4"],
        [("enable_semantic_nn", False)], ["sentence_transformers"], "ml",
        "set enable_semantic_nn=True and `pip install doc-firewall[ml]`",
    ),
    (
        "bert", "BERT prompt-injection classifier", ["T4"], ["T4"],
        [("enable_advanced_bert", False)], ["transformers"], "ml",
        "set enable_advanced_bert=True and `pip install transformers`",
    ),
    (
        "ocr", "OCR injection scan (text in images)", ["T4"], ["T4"],
        [("enable_ocr_injection_scan", False)], ["pytesseract", "PIL"], "ml",
        "set enable_ocr_injection_scan=True and `pip install pytesseract Pillow`",
    ),
    (
        "qr", "QR / barcode decoding (quishing)", ["T10", "T7"], [],
        [("enable_qr_decode", False)], ["pyzbar"], "ml",
        "set enable_qr_decode=True and `pip install pyzbar`",
    ),
    (
        "perplexity", "Perplexity / GCG adversarial-suffix check", ["T4"], [],
        [("enable_perplexity_check", False)], [], None,
        "set enable_perplexity_check=True",
    ),
    (
        "media_metadata", "Audio / video metadata scan", ["T8"], [],
        [("enable_media_metadata_scan", False)], ["mutagen"], "ml",
        "set enable_media_metadata_scan=True and `pip install mutagen`",
    ),
    (
        "ole", "Legacy OLE (.doc/.xls/.ppt) + VBA-stomp parsing", ["T1", "T2"], [],
        [], ["olefile"], "ml",
        "`pip install olefile` to inspect legacy Office binaries",
    ),
]

# Threats whose *baseline* (always-on, no extras) detection is regex/
# structural only — i.e. genuinely weaker without the ML capability.
_ML_DEPENDENT_THREATS = {"T1", "T4"}


@dataclass
class CoverageReport:
    capabilities: List[Capability]

    @property
    def inactive(self) -> List[Capability]:
        return [c for c in self.capabilities if not c.active]

    @property
    def degraded(self) -> bool:
        """True when an ML-dependent threat (T1/T4) has NO active capability."""
        return bool(self.degraded_threats)

    @property
    def degraded_threats(self) -> List[str]:
        # A threat is degraded when none of its *primary* capabilities are
        # active — a format-parsing enabler (e.g. olefile) does not count.
        active_primary = {
            t for c in self.capabilities if c.active for t in c.primary_for
        }
        return sorted(t for t in _ML_DEPENDENT_THREATS if t not in active_primary)

    def threat_status(self) -> Dict[str, str]:
        """Map each threat code touched by an optional capability to
        'active' (>=1 primary capability active), 'baseline-only' (an
        ML-dependent threat with no active primary capability), or
        'partial' (a non-primary helper is active but no primary)."""
        out: Dict[str, str] = {}
        by_threat: Dict[str, List[Capability]] = {}
        for c in self.capabilities:
            for t in c.threats:
                by_threat.setdefault(t, []).append(c)
        for t, caps in by_threat.items():
            primary = [c for c in caps if t in c.primary_for]
            if primary and any(c.active for c in primary):
                out[t] = "active"
            elif t in _ML_DEPENDENT_THREATS:
                out[t] = "baseline-only"
            elif any(c.active for c in caps):
                out[t] = "partial"
            else:
                out[t] = "inactive"
        return out

    def summary_line(self) -> str:
        if not self.degraded:
            n = sum(1 for c in self.capabilities if c.active)
            return f"doc-firewall coverage OK ({n} optional capabilities active)."
        threats = ", ".join(self.degraded_threats)
        return (
            f"doc-firewall running in REDUCED-COVERAGE mode: {threats} have "
            "no active detection capability beyond baseline regex/structural "
            "checks. Inactive: "
            + "; ".join(
                f"{c.label} ({c.remediation})" for c in self.inactive
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "degraded": self.degraded,
            "degraded_threats": self.degraded_threats,
            "threat_status": self.threat_status(),
            "capabilities": [c.to_dict() for c in self.capabilities],
        }


def build_coverage_report(config: Any) -> CoverageReport:
    """Introspect ``config`` + the importable optional packages."""
    caps: List[Capability] = []
    for key, label, threats, primary_for, flags, packages, _extra, remediation in _REGISTRY:
        enabled = all(getattr(config, attr, default) for attr, default in flags)
        # The antivirus capability has no flag — it's active iff an engine
        # is configured.
        if key == "antivirus":
            enabled = getattr(config, "antivirus_engine", None) is not None
        missing = [p for p in packages if not _module_available(p)]
        packages_present = not missing
        active = enabled and packages_present
        caps.append(Capability(
            key=key, label=label, threats=threats, active=active,
            enabled_flag=enabled, packages_present=packages_present,
            primary_for=list(primary_for),
            missing_packages=missing, remediation=remediation,
        ))
    return CoverageReport(capabilities=caps)
