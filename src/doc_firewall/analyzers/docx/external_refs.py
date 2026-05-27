from __future__ import annotations
import re
import zipfile
from typing import List, Dict, Any

try:
    import defusedxml.ElementTree as ET  # noqa: F401
except ImportError as e:
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e
from ...report import Finding
from ...enums import ThreatID, Severity, VerdictClass
from ...config import ScanConfig
from ..base import ParsedDocument

_RELS_FILES = ["_rels/.rels", "word/_rels/document.xml.rels"]

# Schemes that are normal in real-world documents (resume hyperlinks,
# embedded images via https, contact info). External relationships using
# these schemes are not flagged.
_BENIGN_URL_RE = re.compile(
    r"^(?:https?|mailto|tel|sms):", re.IGNORECASE
)
# IP-literal hosts in http(s) URLs — unusual for benign documents.
_IP_LITERAL_HOST = re.compile(
    r"^https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE
)
# Schemes that should never appear in benign external relationships.
_SUSPICIOUS_SCHEME_RE = re.compile(
    r"^(?:javascript|data|vbscript|file|jar|ftp|smb):", re.IGNORECASE
)


def _is_suspicious_target(target: str) -> bool:
    """Return True for external targets that warrant a T2 finding."""
    if not target:
        return False
    t = target.strip()
    if _SUSPICIOUS_SCHEME_RE.match(t):
        return True
    if _IP_LITERAL_HOST.match(t):
        return True
    # Relative path with no scheme — suspicious in an *external* relationship
    # because the value is supposed to be a URL.
    if not _BENIGN_URL_RE.match(t) and "://" not in t:
        return True
    return False


def _parse_rels_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    links = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return links
    for rel in root.findall(".//{*}Relationship"):
        tm = rel.attrib.get("TargetMode", "")
        tgt = rel.attrib.get("Target", "")
        rtype = rel.attrib.get("Type", "")
        rid = rel.attrib.get("Id", "")
        if tm.lower() == "external" and tgt:
            links.append({"id": rid, "type": rtype, "target": tgt, "target_mode": tm})
    return links


def detect_docx_external_refs(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    if doc.file_type != "docx":
        return []
    findings = []
    external_links = []
    parse_errors = []
    try:
        with zipfile.ZipFile(doc.file_path, "r") as z:
            names = set(z.namelist())
            for rel_path in _RELS_FILES:
                if rel_path in names:
                    try:
                        external_links.extend(_parse_rels_xml(z.read(rel_path)))
                    except Exception as e:
                        parse_errors.append(f"{rel_path}: {e}")
    except zipfile.BadZipFile:
        return findings
    suspicious = [
        link for link in external_links if _is_suspicious_target(link.get("target", ""))
    ]
    if suspicious:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.HIGH,
                title="DOCX contains external relationship with suspicious target",
                explain=(
                    "DOCX relationship references a non-standard scheme "
                    "(javascript:/data:/file:/vbscript:/jar:/ftp:/smb:), an "
                    "IP-literal host, or a scheme-less external target. "
                    "Plain http(s)/mailto/tel hyperlinks are not flagged."
                ),
                evidence={
                    "suspicious_links": suspicious,
                    "parse_errors": parse_errors,
                    "malicious_text": suspicious[0]["target"][:250],
                },
                module="docx.external_refs",
                confidence=0.9,
                # Non-standard scheme in an external relationship has no
                # legitimate use in a normal docx — definitive.
                verdict_class=VerdictClass.BLOCK,
            )
        )
    return findings
