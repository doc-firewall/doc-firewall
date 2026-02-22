from __future__ import annotations
import zipfile
from typing import List, Dict, Any

try:
    import defusedxml.ElementTree as ET
except ImportError as e:
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e
from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument

_RELS_FILES = ["_rels/.rels", "word/_rels/document.xml.rels"]


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
    if external_links:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                title="DOCX contains external relationships (links/resources)",
                explain=(
                    "DOCX relationship files reference external targets. "
                    "External relationships can be used to load remote resources "
                    "or track access."
                ),
                evidence={
                    "external_links": external_links,
                    "parse_errors": parse_errors,
                },
                module="docx.external_refs",
            )
        )
    return findings
