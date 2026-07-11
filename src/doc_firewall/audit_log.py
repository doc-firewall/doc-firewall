"""
audit_log.py — Append-only, tamper-evident audit log with a hash chain.

Each log entry is a JSON object written as a single line (JSONL format).
A chain of digests links every entry to the previous one and a monotonic
``seq`` counter numbers them, so retroactive edits and deletions of interior
entries are detectable.

Chain structure:
  entry_N["seq"]        == entry_{N-1}["seq"] + 1   (starts at 0)
  entry_N["prev_hash"]  == entry_{N-1}["entry_hash"]
  entry_N["entry_hash"] == digest(JSON of entry_N without the entry_hash key)

The genesis entry uses prev_hash = "0" * 64.

Trust model — read this before relying on it:

  * **Default (unkeyed SHA-256): tamper-*evident*, not tamper-*proof*.** The
    chain detects in-place edits and interior deletions, but anyone who can
    rewrite the whole file can recompute a fully valid chain, and truncating
    the *tail* is not detectable from the file alone (the ``seq`` counter lets a
    verifier who knows the expected final count catch it — see verify_chain).
  * **Keyed (HMAC-SHA256): tamper-*resistant*.** Set the deployment secret
    ``DOC_FIREWALL_AUDIT_HMAC_KEY`` and the chain digest becomes an HMAC, so an
    attacker who can write the file but does not hold the key cannot forge or
    rewrite valid entries. The *same* key must be present when verifying. For
    strong guarantees, also ship entries to append-only / WORM storage or an
    external witness.

Usage:
  from doc_firewall.audit_log import AuditLog
  log = AuditLog("/var/log/docfirewall/audit.jsonl")
  log.write(report, api_key_id="svc-ingestion", client_ip_hash="sha256-of-ip")

CLI verification (picks up DOC_FIREWALL_AUDIT_HMAC_KEY from the environment):
  doc-firewall audit verify-chain /var/log/docfirewall/audit.jsonl
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .report import ScanReport

_GENESIS_HASH = "0" * 64


def _library_version() -> str:
    """Resolve the installed doc-firewall version so each audit entry stamps
    the real library version rather than a hardcoded (stale) constant."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("doc-firewall")
        except PackageNotFoundError:
            return "unknown"
    except Exception:
        return "unknown"


_VERSION = _library_version()
# Fixed HMAC key for pseudonymisation. This is not a password-hashing key —
# it makes audit field values deterministic and non-reversible for the same
# deployment while allowing cross-entry correlation.  Replace with a
# deployment-specific secret via env var DOC_FIREWALL_PSEUDONYM_KEY for
# stronger privacy guarantees.
import os as _os
_PSEUDONYM_KEY: bytes = _os.environb.get(b"DOC_FIREWALL_PSEUDONYM_KEY", b"doc-firewall-audit-log-v1")


def _audit_hmac_key() -> Optional[bytes]:
    """Deployment secret that upgrades the chain from unkeyed SHA-256 to keyed
    HMAC-SHA256. Read from ``DOC_FIREWALL_AUDIT_HMAC_KEY``; ``None`` (unset or
    empty) keeps the backward-compatible unkeyed chain."""
    raw = _os.environb.get(b"DOC_FIREWALL_AUDIT_HMAC_KEY")
    return raw if raw else None


def _canonical(obj: dict) -> bytes:
    """Stable serialisation of a dict: sorted keys, no whitespace."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def _chain_digest(obj: dict, key: Optional[bytes]) -> str:
    """Chain digest for an entry: keyed HMAC-SHA256 when a deployment key is
    configured (tamper-resistant), else plain SHA-256 (tamper-evident). Both
    are data-integrity constructs, not password storage."""
    data = _canonical(obj)
    if key:
        return hmac.new(key, data, "sha256").hexdigest()
    return hashlib.sha256(data).hexdigest()  # lgtm[py/weak-cryptographic-algorithm]


def _sha256_json(obj: dict) -> str:
    """Stable SHA-256 of a dict: sorted keys, no whitespace. Retained for
    backward compatibility; new code uses :func:`_chain_digest`."""
    return hashlib.sha256(_canonical(obj)).hexdigest()  # lgtm[py/weak-cryptographic-algorithm]


def _hash_optional(value: Optional[str]) -> Optional[str]:
    """Return a deterministic HMAC-SHA256 hex digest for pseudonymization, or None.

    This is pseudonymization of audit metadata (key IDs, IP addresses), not
    password storage.  HMAC-SHA256 with a deployment-specific secret key is the
    correct algorithm here — not a password KDF.
    """
    if value is None:
        return None
    # lgtm[py/weak-cryptographic-algorithm] - pseudonymization, not password hashing
    return hmac.new(_PSEUDONYM_KEY, value.encode("utf-8"), "sha256").hexdigest()


class AuditLog:
    """Thread-safe, append-only audit log with SHA-256 integrity chain."""

    def __init__(self, log_path: str) -> None:
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._prev_hash: str = _GENESIS_HASH
        self._seq: int = -1  # next entry is _seq + 1 → first entry is 0
        self._hmac_key: Optional[bytes] = _audit_hmac_key()

        # Resume chain from last entry if log file already exists
        if self._path.exists():
            self._prev_hash, self._seq = self._read_last_state()

    def _read_last_state(self) -> tuple[str, int]:
        """Return ``(entry_hash, seq)`` of the last entry so a resumed log
        continues the chain and the monotonic counter."""
        last_line = ""
        try:
            with open(self._path, "rb") as fh:
                # Seek backwards to find the last non-empty line
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return _GENESIS_HASH, -1
                pos = size - 1
                while pos >= 0:
                    fh.seek(pos)
                    ch = fh.read(1)
                    if ch == b"\n" and pos < size - 1:
                        line = fh.readline().decode("utf-8", errors="replace").strip()
                        if line:
                            last_line = line
                            break
                    pos -= 1
                if not last_line:
                    # Only one line — read it
                    fh.seek(0)
                    last_line = fh.readline().decode("utf-8", errors="replace").strip()
            if last_line:
                entry = json.loads(last_line)
                seq = entry.get("seq")
                return (
                    entry.get("entry_hash", _GENESIS_HASH),
                    int(seq) if isinstance(seq, int) else -1,
                )
        except Exception:
            pass
        return _GENESIS_HASH, -1

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
            seq = self._seq + 1
            entry: dict = {
                "seq": seq,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "library_version": _VERSION,
                "chain_algo": "hmac-sha256" if self._hmac_key else "sha256",
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
            entry_hash = _chain_digest(entry, self._hmac_key)
            entry["entry_hash"] = entry_hash

            line = json.dumps(entry, separators=(",", ":"), default=str) + "\n"
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)

            self._prev_hash = entry_hash
            self._seq = seq


# ---------------------------------------------------------------------------
# Chain verification (used by CLI and unit tests)
# ---------------------------------------------------------------------------

class ChainVerificationResult:
    def __init__(self) -> None:
        self.entries_checked: int = 0
        self.errors: list[str] = []
        self.last_seq: Optional[int] = None

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    def __str__(self) -> str:
        tail = f" (last seq {self.last_seq})" if self.last_seq is not None else ""
        if self.valid:
            return f"Chain valid — {self.entries_checked} entries verified{tail}."
        return (
            f"Chain INVALID — {len(self.errors)} error(s) in "
            f"{self.entries_checked} entries{tail}:\n"
            + "\n".join(f"  • {e}" for e in self.errors)
        )


def verify_chain(
    log_path: str,
    hmac_key: Optional[bytes] = None,
    expected_count: Optional[int] = None,
) -> ChainVerificationResult:
    """Verify the integrity chain of an audit log file.

    ``hmac_key`` selects the keyed HMAC digest; when ``None`` it falls back to
    ``DOC_FIREWALL_AUDIT_HMAC_KEY`` (so the CLI verifies keyed logs transparently)
    and, if that too is unset, to the unkeyed SHA-256 chain. ``expected_count``,
    if given, is the number of entries the log *should* contain — supply it from
    an external anchor to catch tail-truncation the file alone cannot reveal.

    Returns a ChainVerificationResult describing any tampering found.
    """
    if hmac_key is None:
        hmac_key = _audit_hmac_key()

    result = ChainVerificationResult()
    path = Path(log_path)

    if not path.exists():
        result.errors.append(f"Log file not found: {log_path}")
        return result

    prev_hash = _GENESIS_HASH
    line_num = 0
    expected_seq = 0

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

            # Verify the monotonic sequence counter (detects deleted interior
            # entries). Only enforced for logs that carry it (backward compat).
            seq = entry.get("seq")
            if isinstance(seq, int):
                if seq != expected_seq:
                    result.errors.append(
                        f"Line {line_num}: seq gap — expected {expected_seq}, "
                        f"got {seq} (entries may have been deleted)"
                    )
                    expected_seq = seq
                result.last_seq = seq
                expected_seq += 1

            # Verify prev_hash links to previous entry
            if stored_prev != prev_hash:
                result.errors.append(
                    f"Line {line_num}: prev_hash mismatch "
                    f"(expected {prev_hash[:16]}…, got {stored_prev[:16]}…)"
                )

            # Recompute entry hash (exclude entry_hash field itself)
            recompute_entry = {k: v for k, v in entry.items() if k != "entry_hash"}
            expected_hash = _chain_digest(recompute_entry, hmac_key)
            if expected_hash != stored_hash:
                result.errors.append(
                    f"Line {line_num}: entry_hash mismatch — entry may have been "
                    f"tampered with (expected {expected_hash[:16]}…, "
                    f"got {stored_hash[:16]}…)"
                )

            prev_hash = stored_hash

    # Tail-truncation check against an external anchor, when provided.
    if expected_count is not None and result.entries_checked != expected_count:
        result.errors.append(
            f"Entry count mismatch — expected {expected_count}, found "
            f"{result.entries_checked} (log may have been truncated)"
        )

    return result
