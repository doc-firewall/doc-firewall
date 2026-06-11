"""H.1 (0.4.8) — Evidence contract enforcement.

Contract: every finding that can drive a BLOCK/FLAG decision (severity HIGH
or CRITICAL, or ``verdict_class == BLOCK``) MUST give the reviewer one of:

  1. ``evidence["malicious_text"]`` — the actual offending content (the
     injected prompt, the hidden zero-size-font text, the resolved action
     target, the script body), or
  2. ``evidence["evidence_unavailable_reason"]`` — why the content could not
     be extracted (encrypted stream, unsupported filter, binary region), plus
     ``evidence["debug_steps"]`` — concrete commands the user can run to dig
     the content out of the document themselves.

``apply_evidence_contract()`` is called by the scanner as a post-process,
right after ``enrich_findings()``. It never removes or downgrades findings:

  * If a finding already satisfies the contract it is left untouched.
  * If the offending content exists under a non-canonical evidence key
    (``hidden_text``, ``matched_text``, ``match`` …) it is copied into
    ``malicious_text`` — repairing the finding rather than flagging it.
  * Otherwise the reason + debug steps are attached so the report is
    actionable even when extraction is impossible.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..enums import Severity, VerdictClass
from ..report import Finding

# Evidence keys that, when present and non-empty, contain the actual
# offending content. Ordered by preference — first hit is promoted to
# ``malicious_text``. ``snippet`` is last: it is context around the match,
# still concrete enough for a reviewer.
_FALLBACK_CONTENT_KEYS = (
    "hidden_text",
    "match",
    "matched_text",
    "injected_text",
    "payload",
    "script",
    "command",
    "target",
    "uri",
    "url",
    "formula",
    "infection_phrase",
    "wallet_address",
    "snippet",
)

# Per-format debug recipes. Keys are matched by prefix against the scanner's
# file_type identifiers (``pdf``, ``docx``, ``ole.doc``, ``odf.text`` …).
_DEBUG_STEPS: Dict[str, List[str]] = {
    "pdf": [
        "pdfid.py '{file}'  # count active-content tokens (/JS, /OpenAction, /AA, ...)",
        "pdf-parser.py --search OpenAction '{file}'  # locate the object holding the action",
        "pdf-parser.py --object <N> --filter --raw '{file}'  # decompress and dump object N",
        "qpdf --qdf --object-streams=disable '{file}' decoded.pdf  # rewrite with all streams decoded for manual review",
    ],
    "ooxml": [
        "unzip -l '{file}'  # list the OOXML parts inside the container",
        "unzip -p '{file}' word/document.xml | head -c 5000  # dump the main document part (ppt/slides/*.xml, xl/worksheets/*.xml for pptx/xlsx)",
        "olevba '{file}'  # extract and deobfuscate any VBA macros (oletools)",
        "unzip -p '{file}' docProps/core.xml  # inspect metadata fields",
    ],
    "ole": [
        "olevba '{file}'  # extract VBA macro source (oletools)",
        "oledump.py '{file}'  # list OLE streams",
        "oledump.py -s <N> -v '{file}'  # dump and decompress stream N",
    ],
    "odf": [
        "unzip -l '{file}'  # list ODF parts",
        "unzip -p '{file}' content.xml | head -c 5000  # dump document content",
        "unzip -p '{file}' meta.xml  # inspect metadata fields",
    ],
    "rtf": [
        "rtfdump.py '{file}'  # list RTF groups and embedded objects (oletools)",
        "rtfobj '{file}'  # extract embedded OLE objects",
        "grep -aoE '\\\\\\\\[a-z]+[0-9]*' '{file}' | sort | uniq -c | sort -rn | head  # control-word histogram",
    ],
    "html": [
        "grep -inE '<script|javascript:|onerror=|onload=' '{file}'  # locate active content",
        "grep -inE 'display\\s*:\\s*none|font-size\\s*:\\s*0|opacity\\s*:\\s*0' '{file}'  # locate hidden text styles",
    ],
    "csv": [
        "head -c 2000 '{file}'  # view raw content; look for cells starting with = + - @ (formula injection)",
        "grep -nE '^\\s*[=+@-]|,[=+@-]' '{file}' | head  # locate formula-injection candidates",
    ],
    "archive": [
        "unzip -l '{file}' || tar -tvf '{file}'  # list archive members",
        "Extract to an isolated directory and re-scan each member individually.",
    ],
    "generic": [
        "file '{file}'  # confirm the real file type (magic bytes)",
        "strings -n 8 '{file}' | head -50  # extract printable strings",
        "hexdump -C '{file}' | head -50  # inspect raw bytes",
    ],
}


def _debug_steps_for(file_type: str, file_path: Optional[str]) -> List[str]:
    ft = (file_type or "").lower()
    if ft.startswith("pdf"):
        key = "pdf"
    elif ft.startswith(("docx", "pptx", "xlsx", "docm", "pptm", "xlsm")):
        key = "ooxml"
    elif ft.startswith("ole"):
        key = "ole"
    elif ft.startswith("odf") or ft in ("odt", "ods", "odp"):
        key = "odf"
    elif ft.startswith("rtf"):
        key = "rtf"
    elif ft.startswith(("html", "htm")):
        key = "html"
    elif ft.startswith(("csv", "tsv")):
        key = "csv"
    elif ft.startswith(("zip", "tar")):
        key = "archive"
    else:
        key = "generic"
    fname = file_path or "<file>"
    return [step.format(file=fname) for step in _DEBUG_STEPS[key]]


def _default_reason(f: Finding, file_type: str) -> str:
    ev = f.evidence or {}
    token = str(ev.get("token", ""))
    module = f.module or ""
    if token == "/Encrypt" or "encrypt" in (f.title or "").lower():
        return (
            "The document (or the relevant stream) is encrypted; content "
            "cannot be decoded without the password/key."
        )
    if "fast_scan" in module:
        return (
            "The indicator was matched in the raw file bytes during the fast "
            "scan, which does not parse or decode document objects — the "
            "surrounding content may be compressed, encrypted, or split "
            "across objects, so the exact text could not be extracted."
        )
    return (
        "The detector matched a structural indicator rather than extractable "
        "text; the underlying content may be compressed, encrypted, encoded, "
        "or located in a binary region the scanner does not decode."
    )


def requires_concrete_evidence(f: Finding) -> bool:
    """True when the contract applies to this finding."""
    if f.verdict_class == VerdictClass.INFO:
        return False
    return (
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        or f.verdict_class == VerdictClass.BLOCK
    )


def satisfies_contract(f: Finding) -> bool:
    ev = f.evidence or {}
    mt = ev.get("malicious_text")
    if isinstance(mt, str) and mt.strip():
        return True
    return bool(ev.get("evidence_unavailable_reason")) and bool(ev.get("debug_steps"))


def apply_evidence_contract(
    findings: List[Finding],
    file_type: str = "",
    file_path: Optional[str] = None,
) -> List[Finding]:
    """Mutate ``findings`` in place so every HIGH/CRITICAL/BLOCK finding
    satisfies the evidence contract. Returns the same list."""
    for f in findings:
        if not requires_concrete_evidence(f):
            continue
        ev: Dict[str, Any] = f.evidence if f.evidence is not None else {}
        f.evidence = ev

        mt = ev.get("malicious_text")
        if isinstance(mt, str) and mt.strip():
            continue

        # Repair: promote content held under a non-canonical key.
        promoted = False
        for key in _FALLBACK_CONTENT_KEYS:
            val = ev.get(key)
            if isinstance(val, str) and val.strip():
                ev["malicious_text"] = val[:300]
                ev["malicious_text_source"] = key
                promoted = True
                break
        if promoted:
            continue

        # No extractable content — explain why and how to dig it out.
        ev.setdefault("evidence_unavailable_reason", _default_reason(f, file_type))
        ev.setdefault("debug_steps", _debug_steps_for(file_type, file_path))
    return findings
