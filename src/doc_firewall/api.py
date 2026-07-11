"""REST API microservice for doc-firewall.

Exposes the scanner over HTTP so non-Python backends (Node.js, Go, …) can
submit documents for scanning. Launched via::

    uvicorn doc_firewall.api:app --host 0.0.0.0 --port 8000

or the bundled ``docker-compose-api.yml``. Install the server deps with::

    pip install -e ".[api]"

Endpoints
---------
``GET  /health``  — liveness probe (no auth).
``POST /scan``    — multipart file upload (field ``file``). Optional query
                    params ``profile`` (lenient|balanced|strict) and
                    ``enable_ml`` (bool). Returns the JSON scan report.

Security controls (all driven by ``ScanConfig`` / ``DOC_FIREWALL_*`` env vars)
------------------------------------------------------------------------------
* **API-key auth** — when ``api_keys_path`` points at a JSON key store the
  ``X-API-Key`` header is required and validated against the stored salted
  PBKDF2-HMAC-SHA256 hashes (``doc-firewall audit keygen``). Legacy unsalted
  SHA-256 hashes from older key stores are no longer accepted — rotate any
  such keys. When ``api_keys_path`` is ``None`` the API is open (documented
  behaviour).
* **Per-key rate limiting** — ``api_rate_limit_rpm`` requests/minute/key
  (0 = unlimited), enforced with an in-memory sliding window.
* **Upload cap** — ``api_max_upload_bytes`` bounds the request body so a large
  upload can't exhaust memory (enforced by Content-Length *and* by counting
  streamed bytes, so a lying/absent Content-Length can't bypass it).

This module imports FastAPI at import time; it is only loaded when the API is
actually deployed (uvicorn target), so the base library still installs and runs
without the ``api`` extra.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

try:
    from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
    from fastapi.responses import JSONResponse
except ImportError as exc:  # pragma: no cover - only hit without the api extra
    raise ImportError(
        "The doc-firewall REST API requires FastAPI. Install the API extras: "
        'pip install "doc-firewall[api]"'
    ) from exc

from .config import ScanConfig
from .logger import get_logger
from .scanner import Scanner

logger = get_logger()

app = FastAPI(
    title="doc-firewall",
    description="LLM-aware secure document intake scanner (REST API).",
    version="1",
)


# ── API-key store ────────────────────────────────────────────────────────────
def _load_api_key_entries(path: Optional[str]) -> Optional[List[Dict[str, str]]]:
    """Load the allowed API key entries (salted PBKDF2 hash format) from a
    JSON store.

    Accepts either a bare list of entries or a ``{"keys": [...]}`` wrapper;
    each entry is ``{"id", "name", "hash"}`` (as produced by
    ``doc-firewall audit keygen``). Returns ``None`` when no store is
    configured (open API).
    """
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw_entries = data.get("keys", []) if isinstance(data, dict) else data
    entries = []
    for i, e in enumerate(raw_entries):
        if not isinstance(e, dict) or not e.get("hash"):
            continue
        entries.append({"id": str(e.get("id") or f"key-{i}"), "hash": e["hash"].lower()})
    return entries


def _verify_api_key_legacy_sha256(provided_key: str, stored_hash: str) -> bool:
    """Legacy unsalted-SHA256 API key hashes are no longer accepted (flagged by
    CodeQL as a weak algorithm for credential hashing). Rotate any keys still
    stored in that format with ``doc-firewall audit keygen``, which emits
    salted PBKDF2 hashes."""
    return False


def _verify_api_key_pbkdf2(provided_key: str, stored_hash: str) -> bool:
    # Format: pbkdf2_sha256$<iterations>$<salt_hex>$<derived_key_hex>
    parts = stored_hash.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_dk = bytes.fromhex(parts[3])
    except (ValueError, TypeError):
        return False
    computed_dk = hashlib.pbkdf2_hmac(
        "sha256", provided_key.encode(), salt, iterations, dklen=len(expected_dk)
    )
    return hmac.compare_digest(computed_dk, expected_dk)


def _verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """Validate ``provided_key`` against one stored hash. Only salted PBKDF2
    hashes are accepted; legacy unsalted SHA-256 hashes are rejected."""
    if stored_hash.startswith("pbkdf2_sha256$"):
        return _verify_api_key_pbkdf2(provided_key, stored_hash)
    return _verify_api_key_legacy_sha256(provided_key, stored_hash)


# ── Per-key rate limiter (in-memory sliding window) ──────────────────────────
class _RateLimiter:
    def __init__(self, rpm: int) -> None:
        self.rpm = rpm
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.rpm <= 0:  # 0 = unlimited
            return True
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] < window_start:
                hits.popleft()
            if len(hits) >= self.rpm:
                return False
            hits.append(now)
            return True


# ── App state, built once from config/env ────────────────────────────────────
class _State:
    def __init__(self) -> None:
        self.config = ScanConfig()
        self.api_key_entries = _load_api_key_entries(self.config.api_keys_path)
        self.max_upload = int(self.config.api_max_upload_bytes)
        self.rate_limiter = _RateLimiter(int(self.config.api_rate_limit_rpm))
        # Cache one Scanner per (profile, enable_ml) combination — constructing a
        # Scanner re-runs expensive one-time setup, so we never build one
        # per request.
        self._scanners: Dict[tuple, Scanner] = {}
        self._scanner_lock = threading.Lock()

    def get_scanner(self, profile: str, enable_ml: bool) -> Scanner:
        cache_key = (profile, enable_ml)
        scanner = self._scanners.get(cache_key)
        if scanner is None:
            with self._scanner_lock:
                scanner = self._scanners.get(cache_key)
                if scanner is None:
                    cfg = ScanConfig(profile=profile)
                    if enable_ml:
                        cfg.enable_advanced_ahocorasick = True
                        cfg.enable_advanced_bert = True
                        cfg.enable_advanced_tfidf = True
                        cfg.enable_credential_entropy = True
                    # Carry the deployment's API/auth-independent settings.
                    cfg.audit_log_path = self.config.audit_log_path
                    scanner = self._scanners[cache_key] = Scanner(config=cfg)
        return scanner


_state: Optional[_State] = None
_state_lock = threading.Lock()


def _get_state() -> _State:
    global _state
    if _state is None:
        with _state_lock:
            if _state is None:
                _state = _State()
    return _state


def require_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """Validate the ``X-API-Key`` header against the key store and enforce the
    per-key rate limit. Returns an opaque key id for logging."""
    state = _get_state()

    if state.api_key_entries is None:
        key_id = "anonymous"
    else:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        matched_id = next(
            (e["id"] for e in state.api_key_entries if _verify_api_key(x_api_key, e["hash"])),
            None,
        )
        if matched_id is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        # Rate-limit by the key store's own (non-secret) id label rather than
        # any value derived from the raw key, so no credential material is
        # hashed here at all.
        key_id = f"key:{matched_id}"

    if not state.rate_limiter.allow(key_id):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({state.rate_limiter.rpm} req/min)",
        )
    return key_id


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "doc-firewall"}


@app.post("/scan")
async def scan_endpoint(
    file: UploadFile = File(...),
    profile: str = Query("balanced", pattern="^(lenient|balanced|strict)$"),
    enable_ml: bool = Query(False),
    content_length: Optional[int] = Header(None),
    key_id: str = Depends(require_api_key),
) -> JSONResponse:
    state = _get_state()
    max_upload = state.max_upload

    # Reject early on a declared Content-Length over the cap …
    if content_length is not None and content_length > max_upload:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds limit of {max_upload} bytes",
        )

    # … and enforce the real cap while streaming, so an absent/lying
    # Content-Length can't smuggle an oversized body past the check.
    suffix = os.path.splitext(file.filename or "")[1]
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="docfw_api_", suffix=suffix)
        total = 0
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_upload:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds limit of {max_upload} bytes",
                    )
                out.write(chunk)

        scanner = state.get_scanner(profile, enable_ml)
        report = scanner.scan(tmp_path)
        payload = report.to_dict()
        # The temp path is an internal detail; report the submitted name.
        payload["file_path"] = file.filename
        logger.info(
            "api scan complete",
            key_id=key_id,
            filename=file.filename,
            verdict=report.verdict.value,
        )
        return JSONResponse(content=payload)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("api scan failed", filename=file.filename, error=str(exc))
        raise HTTPException(status_code=500, detail="Scan failed") from exc
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
