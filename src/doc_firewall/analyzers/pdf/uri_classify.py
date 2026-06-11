"""H.5 (0.4.8) — PDF /URI target classification.

Shared by the fast-scan and deep-scan URI checks (kept in sync by import,
not by copy). Splits /URI targets into:

  * ``suspicious`` — javascript:/data:/vbscript:/jar: schemes, IP-literal
    http(s) hosts, ``file://`` URIs with a *remote* host (UNC / NTLM-leak
    vector), and ``file://`` URIs pointing at an executable or script.
  * ``local_artifacts`` — ``file://`` URIs pointing at a *local* document/
    media path. When Office on Windows exports a document to PDF, internal
    ``file://C:/Users/...`` links from the author's machine get baked into
    the PDF's link table. They are leftovers of the author's filesystem,
    not an attack vector — reported as INFO, never BLOCK.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

# javascript:/data:/vbscript:/jar: — no legitimate use in a PDF hyperlink.
# file: is handled separately below with local/remote/executable tiering.
SUSPICIOUS_URI_SCHEMES = re.compile(rb"^(?:javascript|data|vbscript|jar):", re.IGNORECASE)
IP_LITERAL_HOST = re.compile(rb"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)
# Match a /URI ( ... ) entry. Cap inner capture so a malformed PDF can't
# blow up the regex on a giant span.
URI_ENTRY_RE = re.compile(rb"/URI\s*\(([^)\\]{1,2000})\)")

_FILE_SCHEME_RE = re.compile(rb"^file:(?P<rest>.*)$", re.IGNORECASE)
_DRIVE_RE = re.compile(rb"^[A-Za-z][:|]$")
_EXEC_EXT_RE = re.compile(
    rb"\.(?:exe|js|jse|vbs|vbe|hta|lnk|scr|cmd|bat|ps1|psm1|jar|msi|msp|"
    rb"com|pif|wsf|wsh|dll|cpl|reg|iso|img|application|appref-ms)\s*$",
    re.IGNORECASE,
)


def _file_uri_host(rest: bytes) -> bytes:
    """Extract the host of a file: URI body (b'' when local)."""
    if not rest.startswith(b"//"):
        return b""
    after = rest[2:]
    if after[:1] in (b"/", b"\\"):
        return b""  # file:///path — empty authority, local
    # file://C:/... → the first token is a drive letter, not a host
    host = re.split(rb"[/\\]", after, maxsplit=1)[0]
    if not host or _DRIVE_RE.match(host) or host.lower() == b"localhost":
        return b""
    return host


def classify_pdf_uris(blob: bytes) -> Tuple[List[Dict], List[Dict]]:
    """Return ``(suspicious, local_artifacts)`` for all /URI entries.

    Each entry is ``{"target": str}`` plus a ``"reason"`` for file:-scheme
    suspicious hits. Capped at 20 entries per bucket.
    """
    suspicious: List[Dict] = []
    artifacts: List[Dict] = []
    for m in URI_ENTRY_RE.finditer(blob):
        target = m.group(1).strip()
        decoded = target.decode("latin-1", errors="replace")[:200]

        fm = _FILE_SCHEME_RE.match(target)
        if fm:
            if _file_uri_host(fm.group("rest").strip()):
                suspicious.append({
                    "target": decoded,
                    "reason": (
                        "file:// URI with a remote host — opening it can leak "
                        "NTLM credentials to the attacker's server (UNC vector)"
                    ),
                })
            elif _EXEC_EXT_RE.search(target):
                suspicious.append({
                    "target": decoded,
                    "reason": "file:// URI pointing at an executable or script",
                })
            else:
                if len(artifacts) < 20:
                    artifacts.append({"target": decoded})
        elif SUSPICIOUS_URI_SCHEMES.match(target) or IP_LITERAL_HOST.match(target):
            suspicious.append({"target": decoded})

        if len(suspicious) >= 20:
            break
    return suspicious, artifacts
