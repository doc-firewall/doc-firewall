"""
audit_log.py — Append-only tamper-evident audit log with SHA-256 hash chain.

Each log entry is a JSON object written as a single line (JSONL format).
A chain of SHA-256 hashes links every entry to the previous one, making
retroactive tampering detectable without an external witness service.

Chain structure:
  entry_N["prev_hash"]  == entry_{N-1}["entry_hash"]
  entry_N["entry_hash"] == SHA-256(JSON of entry_N without the entry_hash key)

The genesis entry uses prev_hash = "0" * 64.

Usage:
  from doc_firewall.audit_log import AuditLog
  log = AuditLog("/var/log/docfirewall/audit.jsonl")
  log.write(report, api_key_id="svc-ingestion", client_ip_hash="sha256-of-ip")

CLI verification:
  doc-firewall audit verify-chain /var/log/docfirewall/audit.jsonl
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .report import ScanReport

_GENESIS_HASH = "0" * 64
_VERSION = "0.4.0"


def _sha256_json(obj: dict) -> str:
    """Stable SHA-256 of a dict: sorted keys, no whitespace."""
    # SHA-256 is the correct algorithm for a tamper-evident hash chain —
    # this is data-integrity hashing, not password storage.
    serialised = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()  # lgtm[py/weak-cryptographic-algorithm]


def _hash_optional(value: Optional[str]) -> Optional[str]:
    """Return a SHA-256 hex digest for pseudonymization, or None."""
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()  # lgtm[py/weak-cryptographic-algorithm]


class AuditLog:
    """Thread-safe, append-only audit log with SHA-256 integrity chain."""

    def __init__(self, log_path: str) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._prev_hash: str = _GENESIS_HASH

        # Resume chain from last entry if log file already exists
        if self._path.exists():
            self._prev_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        try:
            with open(self._path, "rb") as fh:
                # Seek backwards to find the last non-empty line
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return _GENESIS_HASH
                pos = size - 1
                while pos >= 0:
                    fh.seek(pos)
                    ch = fh.read(1)
                    if ch == b"\n" and pos < size - 1:
                        line = fh.readline().decode("utf-8", errors="replace").strip()
                        if line:
                            entry = json.loads(line)
                            return entry.get("entry_hash", _GENESIS_HASH)
                    pos -= 1
                # Only one line — read it
                fh.seek(0)
                line = fh.readline().decode("utf-8", errors="replace").strip()
                if line:
                    entry = json.loads(line)
                    return entry.get("entry_hash", _GENESIS_HASH)
        except Exception:
            pass
        return _GENESIS_HASH

    def write(
        self,
        report: ScanReport,
        api_key_id: Optional[str] = None,
        client_ip_hash: Optional[str] = None,
    ) -> None:
        """Append one audit entry for the given scan report."""
        self._path.parent.mkdir(parents=True, exist_ok=True)

        threat_ids = list({f.threat_id.value for f in report.findings})
        processing_ms = sum(report.timings_ms.values())

        with self._lock:
            entry: dict = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "library_version": _VERSION,
                "file_sha256": report.sha256,
                "file_type": report.file_type,
                "size_bytes": report.size_bytes,
                "verdict": report.verdict.value,
                "risk_score": round(report.risk_score, 6),
                "threat_ids": sorted(threat_ids),
                "finding_count": len(report.findings),
                "api_key_id_hash": _hash_optional(api_key_id),  # pseudonymised; never store plaintext key id
                "client_ip_hash": client_ip_hash,
                "processing_ms": round(processing_ms, 3),
                "prev_hash": self._prev_hash,
            }
            entry_hash = _sha256_json(entry)
            entry["entry_hash"] = entry_hash

            line = json.dumps(entry, separators=(",", ":"), default=str) + "\n"
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)

            self._prev_hash = entry_hash


# ---------------------------------------------------------------------------
# Chain verification (used by CLI and unit tests)
# ---------------------------------------------------------------------------

class ChainVerificationResult:
    def __init__(self) -> None:
        self.entries_checked: int = 0
        self.errors: list[str] = []

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def __str__(self) -> str:
        if self.valid:
            return f"Chain valid — {self.entries_checked} entries verified."
        return (
            f"Chain INVALID — {len(self.errors)} error(s) in "
            f"{self.entries_checked} entries:\n"
            + "\n".join(f"  • {e}" for e in self.errors)
        )


def verify_chain(log_path: str) -> ChainVerificationResult:
    """Verify the integrity chain of an audit log file.

    Returns a ChainVerificationResult describing any tampering found.
    """
    result = ChainVerificationResult()
    path = Path(log_path)

    if not path.exists():
        result.errors.append(f"Log file not found: {log_path}")
        return result

    prev_hash = _GENESIS_HASH
    line_num = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            line_num += 1
            result.entries_checked += 1

            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                result.errors.append(f"Line {line_num}: JSON parse error — {exc}")
                continue

            stored_hash = entry.get("entry_hash", "")
            stored_prev = entry.get("prev_hash", "")

            # Verify prev_hash links to previous entry
            if stored_prev != prev_hash:
                result.errors.append(
                    f"Line {line_num}: prev_hash mismatch "
                    f"(expected {prev_hash[:16]}…, got {stored_prev[:16]}…)"
                )

            # Recompute entry hash (exclude entry_hash field itself)
            recompute_entry = {k: v for k, v in entry.items() if k != "entry_hash"}
            expected_hash = _sha256_json(recompute_entry)
            if expected_hash != stored_hash:
                result.errors.append(
                    f"Line {line_num}: entry_hash mismatch — entry may have been "
                    f"tampered with (expected {expected_hash[:16]}…, "
                    f"got {stored_hash[:16]}…)"
                )

            prev_hash = stored_hash

    return result
