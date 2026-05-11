"""
api_auth.py — API key validation and token-bucket rate limiting.

Key store format (JSON file pointed to by ScanConfig.api_keys_path):
  {
    "keys": [
      {"id": "svc-ingestion", "name": "Ingestion pipeline", "hash": "<sha256-hex>"},
      ...
    ]
  }

The raw key is NEVER stored.  Only its SHA-256 hex digest is kept on disk.
Clients send the raw key in the X-API-Key header; the middleware hashes it
and compares against stored digests.

Rate limiting: in-memory token bucket, one bucket per key id.  State is
process-local and resets on restart — suitable for single-instance deployments.
For multi-node HA, move bucket state to Redis (Phase 2).
"""
from __future__ import annotations

import hashlib
import json
import time
import threading
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Key store
# ---------------------------------------------------------------------------

class KeyStore:
    """Loads and validates API keys from a JSON file."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._keys: dict[str, str] = {}  # hash → id
        self._lock = threading.Lock()
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
        except Exception as exc:
            raise RuntimeError(f"Failed to load API key store from {self._path}: {exc}") from exc

    def reload(self) -> None:
        """Hot-reload key store from disk (call on SIGHUP)."""
        self._load()

    def validate(self, raw_key: str) -> Optional[str]:
        """Return key id if valid, None otherwise."""
        digest = hashlib.sha256(raw_key.encode()).hexdigest()
        with self._lock:
            return self._keys.get(digest)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        """Utility: compute the hash to store in the key store JSON."""
        return hashlib.sha256(raw_key.encode()).hexdigest()


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
