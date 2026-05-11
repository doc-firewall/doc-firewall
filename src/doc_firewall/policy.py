"""Policy Engine — named scan policies with allow/deny lists and per-threat tuning.

Policies are loaded from a YAML file and resolved per scan request. The engine
is thread-safe so it can be reloaded at runtime (e.g., on SIGHUP) without
restarting the scanner.
"""
from __future__ import annotations

import fnmatch
import os
import threading
from typing import Optional

from pydantic import BaseModel, Field


class AllowEntry(BaseModel):
    """A pre-approved document hash — scanning is skipped, verdict is ALLOW."""
    sha256: str
    comment: Optional[str] = None


class DenyEntry(BaseModel):
    """A permanently blocked document hash — verdict is BLOCK without scanning."""
    sha256: str
    comment: Optional[str] = None


class Policy(BaseModel):
    """A named scan policy applied to matching files."""

    name: str
    applies_to: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Glob patterns matched against the file's basename. First matching policy wins.",
    )
    profile: str = Field(
        "balanced",
        description="Threshold profile: lenient | balanced | strict",
    )
    required_detectors: list[str] = Field(
        default_factory=list,
        description="Threat IDs (e.g. 'T4', 'T9') that MUST fire for the verdict to be trusted. "
                    "Missing detectors are recorded in report.metadata['missing_required_detectors'].",
    )
    custom_threat_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Per-threat weight overrides, keyed by ThreatID value (e.g. 'T9_ATS_MANIPULATION': 0.9).",
    )
    allow_list: list[AllowEntry] = Field(
        default_factory=list,
        description="SHA-256 hashes of pre-approved documents. Matched files skip all scanning.",
    )
    deny_list: list[DenyEntry] = Field(
        default_factory=list,
        description="SHA-256 hashes of permanently blocked documents. Matched files are blocked without scanning.",
    )

    def matches_file(self, file_path: str) -> bool:
        basename = os.path.basename(file_path)
        return any(fnmatch.fnmatch(basename, pat) for pat in self.applies_to)

    @property
    def allow_hashes(self) -> frozenset[str]:
        return frozenset(e.sha256.lower() for e in self.allow_list)

    @property
    def deny_hashes(self) -> frozenset[str]:
        return frozenset(e.sha256.lower() for e in self.deny_list)


class PolicyFile(BaseModel):
    policies: list[Policy] = Field(default_factory=list)


class PolicyEngine:
    """Loads and resolves named scan policies from a YAML policy file.

    Thread-safe: ``reload()`` can be called from a SIGHUP handler while
    scans are in progress on other threads.

    Usage::

        engine = PolicyEngine("policies.yaml")
        policy = engine.get_for_file("resume.pdf", policy_name="hr-intake")

        import signal
        signal.signal(signal.SIGHUP, lambda *_: engine.reload())
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._policy_file: Optional[PolicyFile] = None
        self.load()

    def load(self) -> None:
        """Load (or reload) the policy file from disk."""
        import yaml  # PyYAML — already a doc-firewall dependency via ScanConfig.from_yaml

        with open(self._path, "r") as f:
            data = yaml.safe_load(f) or {}
        pf = PolicyFile(**data)
        with self._lock:
            self._policy_file = pf

    def reload(self) -> None:
        """Hot-reload the policy file without restarting. Call from SIGHUP handler."""
        self.load()

    def resolve(self, name: str) -> Optional[Policy]:
        """Return the policy with the given name, or None if not found."""
        with self._lock:
            if self._policy_file is None:
                return None
            for p in self._policy_file.policies:
                if p.name == name:
                    return p
        return None

    def get_for_file(
        self,
        file_path: str,
        policy_name: Optional[str] = None,
    ) -> Optional[Policy]:
        """Return the best-matching policy for a file.

        If *policy_name* is given, resolve by name (exact match).
        Otherwise, return the first policy whose ``applies_to`` globs match
        the file's basename. Returns ``None`` when no policy matches.
        """
        if policy_name:
            return self.resolve(policy_name)
        with self._lock:
            if self._policy_file is None:
                return None
            for p in self._policy_file.policies:
                if p.matches_file(file_path):
                    return p
        return None

    @property
    def policy_names(self) -> list[str]:
        with self._lock:
            if self._policy_file is None:
                return []
            return [p.name for p in self._policy_file.policies]
