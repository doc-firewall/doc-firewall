# Docker API

The Docker image encapsulates the scanner and dependencies (ClamAV, Docling models).

## Dockerfile

The official image allows environment variable configuration.

```dockerfile
FROM doc-firewall:latest
ENV DOC_FIREWALL__PROFILE=strict
```

## Environment Variables

All `ScanConfig` options can be set via environment variables using the `DOC_FIREWALL_` prefix and double underscores for nesting.

| Variable | Config Path | Example |
|---|---|---|
| `DOC_FIREWALL_PROFILE` | `profile` | `strict` |
| `DOC_FIREWALL_ENABLE_ANTIVIRUS` | `enable_antivirus` | `true` |
| `DOC_FIREWALL_ANTIVIRUS__PROVIDER` | `antivirus.provider` | `virustotal` |
| `DOC_FIREWALL_LIMITS__MAX_MB` | `limits.max_mb` | `50` |

## Volume Mounts

-   `/app/dataset`: Working directory for bulk scans.
-   `/root/.cache`: Model cache (mount to persist Docling/RapidOCR models).
