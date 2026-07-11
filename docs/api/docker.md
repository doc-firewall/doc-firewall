# Docker API

The Docker image encapsulates the scanner and all dependencies (ClamAV, Docling models).
Configuration is driven entirely by environment variables, making it suitable for
secrets managers, Kubernetes ConfigMaps, and CI/CD pipelines without rebuilding the image.

---

## Quick Start

```bash
# Start the API in detached mode
docker-compose -f docker-compose-api.yml up -d

# Smoke-test the running container
curl -F "file=@sample.pdf" http://localhost:8000/scan
```

The API listens on port `8000`. On a successful scan the response body is a JSON
`ScanResult` object; on error a `422` or `413` is returned with a detail message.

---

## Endpoints

The service is a thin ASGI wrapper (`doc_firewall.api:app`) over the scanner.

| Method & path | Auth | Description |
|---|---|---|
| `GET /health` | none | Liveness probe → `{"status": "ok"}`. |
| `POST /scan` | API key (if configured) | Multipart upload; field `file`. Optional query params `profile` (`lenient\|balanced\|strict`) and `enable_ml` (bool). Returns the JSON scan report. |

```bash
# Scan with the strict profile and ML detectors enabled
curl -X POST -F "file=@suspicious.pdf" \
  "http://localhost:8000/scan?profile=strict&enable_ml=true"
```

### Authentication

When `api_keys_path` (env `DOC_FIREWALL_API_KEYS_PATH`) points at a JSON key
store, `POST /scan` requires an `X-API-Key` header; the raw key is verified
against the stored salted PBKDF2-HMAC-SHA256 hash. Legacy unsalted SHA-256
key-store entries are no longer accepted and must be regenerated with
`doc-firewall audit keygen`. When `api_keys_path` is unset, the API is open
(no auth) — do not expose it publicly in that mode.

Generate a key + hash pair with the CLI, then add the printed JSON entry to the
key store:

```bash
doc-firewall audit keygen --name "intake-service"
```

The store is a JSON array of `{"id", "name", "hash"}` entries (a
`{"keys": [...]}` wrapper is also accepted).

| Status | Meaning |
|---|---|
| `401` | Missing or invalid `X-API-Key` (when a key store is configured) |
| `413` | Upload exceeds `api_max_upload_bytes` |
| `429` | Per-key rate limit (`api_rate_limit_rpm`) exceeded |
| `500` | Scan failed unexpectedly |

---

## Security Hardening (3.6)

Release 3.6 applies defence-in-depth hardening directly in `docker-compose-api.yml`.
No additional configuration is required — the options below are active by default.

### Read-Only Filesystem

```yaml
read_only: true
tmpfs:
  - /tmp:size=256m,mode=1777      # parsing scratch space
  - /run:size=32m,mode=0755       # runtime sockets / pid files
  - /var/log/docfw:size=64m       # audit log output
```

The container root filesystem is mounted read-only. Only the three `tmpfs` paths
listed above accept writes at runtime:

| Path | Purpose |
|---|---|
| `/tmp` | Temporary files created during document parsing |
| `/run` | Unix sockets and PID files for uvicorn |
| `/var/log/docfw` | Audit log output; replace with a named volume in production to persist logs |

Any attempt by a compromised process to modify the image layers or application code
will fail with a permission error.

### Seccomp Profile

```yaml
security_opt:
  - seccomp:docker/seccomp.json
```

`docker/seccomp.json` is a curated allowlist profile. It blocks syscalls that are
not needed by the scanner and that are commonly abused in container-escape attacks:

| Blocked syscall | Why it is blocked |
|---|---|
| `ptrace` | Prevents process inspection / code injection |
| `clone` with `CLONE_NEWUSER` | Prevents unprivileged user-namespace creation |
| `mount` | Prevents filesystem manipulation from inside the container |

All syscalls required by Python, uvicorn, ClamAV, and Docling are explicitly
permitted in the allowlist.

### No New Privileges

```yaml
security_opt:
  - no-new-privileges:true
```

Prevents any child process from gaining elevated privileges through `setuid`/`setgid`
binaries or Linux capability-raising calls, even if such binaries are present in the
image.

### Capability Drop

```yaml
cap_drop:
  - ALL
```

All Linux capabilities are dropped. The uvicorn worker process requires no capabilities
beyond the default unprivileged set, so none are re-added.

### CPU and Memory Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: "2.0"
      memory: 2G
    reservations:
      memory: 512M
```

Hard limits prevent a single container from exhausting host resources under
adversarially crafted inputs (e.g., decompression bombs, deeply nested archives).
Tune `cpus` and `memory` to match the capacity of your host before deploying.

---

## Environment Variables

All `ScanConfig` fields can be set via environment variables using the `DOC_FIREWALL_`
prefix. Nested fields use double underscores (`__`) as separators.

| Variable | Config field | Example |
|---|---|---|
| `DOC_FIREWALL_PROFILE` | `profile` | `strict` |
| `DOC_FIREWALL_ENABLE_ANTIVIRUS` | `enable_antivirus` | `true` |
| `DOC_FIREWALL_ANTIVIRUS__PROVIDER` | `antivirus.provider` | `virustotal` |
| `DOC_FIREWALL_LIMITS__MAX_MB` | `limits.max_mb` | `50` |
| `DOC_FIREWALL_POLICY_PATH` | `policy_path` | `/etc/docfw/policy.yaml` |
| `DOC_FIREWALL_POLICY_NAME` | `policy_name` | `hr-intake` |
| `DOC_FIREWALL_VERIFY_MODEL_INTEGRITY` | `verify_model_integrity` | `true` |
| `DOC_FIREWALL_MODEL_INTEGRITY_MANIFEST_PATH` | `model_integrity_manifest_path` | `/etc/docfw/model_manifest.json` |
| `DOC_FIREWALL_API_MAX_UPLOAD_BYTES` | `api_max_upload_bytes` | `20971520` |
| `DOC_FIREWALL_API_RATE_LIMIT_RPM` | `api_rate_limit_rpm` | `60` |

| `DOC_FIREWALL_API_KEYS_PATH` | `api_keys_path` | `/etc/docfw/api_keys.json` |

`DOC_FIREWALL_API_MAX_UPLOAD_BYTES` defaults to `20971520` (20 MB).
`DOC_FIREWALL_API_RATE_LIMIT_RPM` defaults to `60` requests per minute **per API
key** (`0` = unlimited). When no key store is configured, all requests share a
single `anonymous` bucket.

---

## Volume Mounts

The recommended production volume layout separates read-only configuration and model
assets from writable log output:

| Mount | Mode | Contents |
|---|---|---|
| `/app/models:ro` | Read-only | Pre-downloaded ML model weights (Docling, RapidOCR). Mount this to avoid downloading models on every container start. |
| `/etc/docfw:ro` | Read-only | Runtime configuration: `api_keys.json`, `policy.yaml`, `model_manifest.json`. |
| `/var/log/docfw` | Read-write | Audit log output. Use a named Docker volume for persistence, or leave as `tmpfs` for ephemeral/stateless deployments. |

Example `docker-compose` override for production:

```yaml
volumes:
  - /data/docfw/models:/app/models:ro
  - /etc/docfw:/etc/docfw:ro
  - docfw-logs:/var/log/docfw

volumes:
  docfw-logs:
```

---

## SBOM

A Software Bill of Materials (SBOM) in CycloneDX JSON format can be generated with:

```bash
make sbom
```

The SBOM lists every Python package and system dependency included in the image,
along with version and license metadata. It can also be baked directly into the
image at build time using Docker's `--attest sbom` flag or a `COPY` step, making
it available via `docker buildx imagetools inspect` for supply-chain verification.
