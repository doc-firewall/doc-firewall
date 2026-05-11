"""
api_auth.py — API key validation and token-bucket rate limiting.

Key store format (JSON file pointed to by ScanConfig.api_keys_path):
  {
    "keys": [
      {"id": "svc-ingestion", "name": "Ingestion pipeline", "hash": "<sha256-hex>"},
      ...
    ]
  }

The raw key is NEVER stored.  Only its hash digest is kept on disk.
New keys use PBKDF2-HMAC-SHA256 (stored as 'pbkdf2_sha256$iters$salt$dk').
Legacy entries may use a plain SHA-256 hex digest; both formats are accepted.

Validation cache: after the first successful PBKDF2 verification the result
is cached (keyed on HMAC-SHA256 of the raw key) for CACHE_TTL_S seconds so
that repeat requests do not pay the PBKDF2 cost on every call.

Rate limiting: in-memory token bucket, one bucket per key id.  State is
process-local and resets on restart — suitable for single-instance deployments.
For multi-node HA, move bucket state to Redis (Phase 2).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import threading
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Key store
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 310_000
_PBKDF2_SALT_BYTES = 16
# TTL for the in-process validation cache (seconds).  Keeps PBKDF2 cost
# off the hot path while bounding how long a revoked key stays valid.
_CACHE_TTL_S = 300
# HMAC key used only to derive the cache lookup token — never stored.
_CACHE_HMAC_KEY: bytes = os.environb.get(b"DOC_FIREWALL_CACHE_KEY", b"doc-firewall-key-cache-v1")


class KeyStore:
    """Loads and validates API keys from a JSON file."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._keys: dict[str, str] = {}  # stored_hash → id
        self._lock = threading.Lock()
        # cache: {hmac_token: (key_id, expiry_monotonic)}
        self._cache: dict[str, tuple[str, float]] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            with self._lock:
                self._keys = {
                    entry["hash"]: entry["id"]
                    for entry in data.get("keys", [])
                    if "hash" in entry and "id" in entry
                }
                self._cache.clear()  # invalidate cache on reload
        except Exception as exc:
            raise RuntimeError(f"Failed to load API key store from {self._path}: {exc}") from exc

    def reload(self) -> None:
        """Hot-reload key store from disk (call on SIGHUP)."""
        self._load()

    @staticmethod
    def _verify_key(raw_key: str, stored_hash: str) -> bool:
        """Verify raw_key against a stored hash (PBKDF2 or legacy SHA-256)."""
        parts = stored_hash.split("$")
        if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
            try:
                iterations = int(parts[1])
                salt = bytes.fromhex(parts[2])
                expected = bytes.fromhex(parts[3])
            except (ValueError, TypeError):
                return False
            candidate = hashlib.pbkdf2_hmac("sha256", raw_key.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(candidate, expected)
        # Legacy: plain SHA-256 hex
        candidate_legacy = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()  # lgtm[py/weak-cryptographic-algorithm]
        return hmac.compare_digest(candidate_legacy, stored_hash)

    def validate(self, raw_key: str) -> Optional[str]:
        """Return key id if valid, None otherwise.

        Results are cached for _CACHE_TTL_S seconds so PBKDF2 is only
        computed once per unique key per TTL window.
        """
        cache_token = hmac.new(_CACHE_HMAC_KEY, raw_key.encode(), "sha256").hexdigest()
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(cache_token)
            if cached is not None and cached[1] > now:
                return cached[0]
            for stored_hash, key_id in self._keys.items():
                if self._verify_key(raw_key, stored_hash):
                    self._cache[cache_token] = (key_id, now + _CACHE_TTL_S)
                    return key_id
        return None

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Compute a PBKDF2-HMAC-SHA256 hash suitable for the key store JSON.

        Returns a string in the format::
            pbkdf2_sha256$<iterations>$<salt_hex>$<dk_hex>
        """
        salt = os.urandom(_PBKDF2_SALT_BYTES)
        dk = hashlib.pbkdf2_hmac("sha256", raw_key.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
        return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class _Bucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, capacity: float) -> None:
        self.tokens = capacity
        self.last_refill = time.monotonic()


class RateLimiter:
    """Per-key token bucket.  Thread-safe, in-memory."""

    def __init__(self, requests_per_minute: int) -> None:
        self._rpm = requests_per_minute
        self._capacity = float(max(requests_per_minute, 1))
        self._refill_rate = self._capacity / 60.0  # tokens per second
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key_id: str) -> bool:
        """Return True if the request is within the rate limit."""
        if self._rpm == 0:
            return True
        now = time.monotonic()
        with self._lock:
            if key_id not in self._buckets:
                self._buckets[key_id] = _Bucket(self._capacity)
            bucket = self._buckets[key_id]
            elapsed = now - bucket.last_refill
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._refill_rate)
            bucket.last_refill = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False
