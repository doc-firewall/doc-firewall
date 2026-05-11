"""
api.py — FastAPI REST microservice for DocFirewall.

Security controls (Phase 1):
  - API key authentication via X-API-Key header (optional; off when no key
    store is configured so existing deployments are unaffected)
  - Per-key token-bucket rate limiting (configurable rpm)
  - Hard Content-Length check before any file is buffered
  - MIME / extension validation before the scanner touches the file
  - Generic error responses — internal details go to structured log only
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import traceback
import uuid
from typing import Optional

from fastapi import FastAPI, File, Request, UploadFile, Query, HTTPException
from fastapi.responses import JSONResponse

from .scanner import Scanner
from .config import ScanConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (loaded once at startup)
# ---------------------------------------------------------------------------

_key_store = None   # KeyStore | None
_rate_limiter = None  # RateLimiter | None
_global_config: Optional[ScanConfig] = None


def _get_or_build_config() -> ScanConfig:
    global _global_config
    if _global_config is None:
        _global_config = ScanConfig()
    return _global_config


def _get_key_store():
    global _key_store
    if _key_store is None:
        cfg = _get_or_build_config()
        if cfg.api_keys_path:
            from .api_auth import KeyStore
            _key_store = KeyStore(cfg.api_keys_path)
    return _key_store


def _get_rate_limiter():
    global _rate_limiter
    if _rate_limiter is None:
        cfg = _get_or_build_config()
        from .api_auth import RateLimiter
        _rate_limiter = RateLimiter(cfg.api_rate_limit_rpm)
    return _rate_limiter


# ---------------------------------------------------------------------------
# Allowed upload extensions / MIME prefixes
# ---------------------------------------------------------------------------

_ALLOWED_EXTENSIONS = {".pdf", ".docx", ".docm", ".pptx", ".pptm",
                       ".xlsx", ".xlsm", ".xlsb", ".rtf", ".html", ".htm"}

_ALLOWED_CONTENT_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/rtf",
    "text/rtf",
    "text/html",
    "application/octet-stream",  # generic binary — extension check is the gate
}


def _validate_upload(file: UploadFile, max_bytes: int) -> None:
    """Raise HTTPException if the upload fails basic validation checks."""
    filename = file.filename or ""
    ext = os.path.splitext(filename.lower())[1]
    if ext and ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Unsupported file type.")

    # Content-type check (advisory — clients can lie, so extension wins)
    ct = (file.content_type or "").split(";")[0].strip().lower()
    if ct and ct not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=415, detail="Unsupported content type.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DocFirewall Microservice",
    description="Drop-in REST API for DocFirewall zero-trust document scanning.",
    version="0.4.0",
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Enforce authentication, rate limiting, and Content-Length limits."""
    cfg = _get_or_build_config()
    trace_id = str(uuid.uuid4())
    request.state.trace_id = trace_id

    # ── 1. Content-Length hard limit ────────────────────────────────────────
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > cfg.api_max_upload_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request entity too large.", "trace_id": trace_id},
                )
        except ValueError:
            pass

    # ── 2. API key auth (skip if no key store is configured) ────────────────
    ks = _get_key_store()
    key_id = None
    if ks is not None and request.url.path != "/health":
        raw_key = request.headers.get("x-api-key", "")
        key_id = ks.validate(raw_key)
        if key_id is None:
            return JSONResponse(
                status_code=401,
                content={"error": "Invalid or missing API key.", "trace_id": trace_id},
            )
        request.state.key_id = key_id

    # ── 3. Rate limiting ────────────────────────────────────────────────────
    if key_id and cfg.api_rate_limit_rpm > 0:
        rl = _get_rate_limiter()
        if not rl.allow(key_id):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded.", "trace_id": trace_id},
                headers={"Retry-After": str(60 // max(cfg.api_rate_limit_rpm, 1))},
            )

    response = await call_next(request)
    response.headers["X-Trace-Id"] = trace_id
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan_document(
    request: Request,
    file: UploadFile = File(...),
    profile: str = Query("balanced", description="lenient | balanced | strict"),
    enable_ml: bool = Query(False, description="Enable local deep learning detectors"),
):
    trace_id = getattr(request.state, "trace_id", "unknown")
    cfg = _get_or_build_config()

    # Validate upload before touching disk
    _validate_upload(file, cfg.api_max_upload_bytes)

    scan_config = ScanConfig(profile=profile)
    if enable_ml:
        scan_config.enable_advanced_ahocorasick = True
        scan_config.enable_advanced_bert = True
        scan_config.enable_advanced_tfidf = True
        scan_config.enable_credential_entropy = True

    scanner = Scanner(config=scan_config)
    suffix = os.path.splitext(file.filename or "")[1] or ".bin"

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name

        report = scanner.scan(tmp_path)
        return JSONResponse(status_code=200, content=report.to_dict())

    except HTTPException:
        raise
    except Exception:
        # Log full detail internally; return only a trace ID to the caller.
        logger.error(
            "Scan failed trace_id=%s\n%s", trace_id, traceback.format_exc()
        )
        raise HTTPException(
            status_code=500,
            detail=f"Internal error. Reference trace_id={trace_id}",
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
