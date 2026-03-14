from __future__ import annotations
import zipfile
from typing import Any, Dict, List

try:
    import defusedxml.ElementTree as ET  # noqa: F401
except ImportError as e:
    raise ImportError(
        "defusedxml is required for safe XML parsing of untrusted documents. "
        "Install it with: pip install defusedxml"
    ) from e

from ...report import Finding
from ...enums import ThreatID, Severity
from ...config import ScanConfig
from ..base import ParsedDocument

# Key relationship files to check in XLSX packages
_RELS_PATHS = [
    "_rels/.rels",
    "xl/_rels/workbook.xml.rels",
]


def _parse_rels_xml(xml_bytes: bytes) -> List[Dict[str, Any]]:
    links: List[Dict[str, Any]] = []
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
            if not rtype.endswith("relationships/hyperlink"):
                links.append(
                    {"id": rid, "type": rtype, "target": tgt, "target_mode": tm}
                )
    return links


def detect_xlsx_external_refs(doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
    """Detect external relationships in an XLSX file."""
    if doc.file_type != "xlsx":
        return []
    findings: List[Finding] = []
    external_links: List[Dict[str, Any]] = []
    parse_errors: List[str] = []

    try:
        with zipfile.ZipFile(doc.file_path, "r") as zf:
            names = set(zf.namelist())
            # Check known rels paths
            for rel_path in _RELS_PATHS:
                if rel_path in names:
                    try:
                        external_links.extend(_parse_rels_xml(zf.read(rel_path)))
                    except Exception as e:
                        parse_errors.append(f"{rel_path}: {e}")
            # Also scan worksheet .rels files
            for name in names:
                if name.startswith("xl/worksheets/_rels/") and name.endswith(".rels"):
                    try:
                        external_links.extend(_parse_rels_xml(zf.read(name)))
                    except Exception as e:
                        parse_errors.append(f"{name}: {e}")

            # XLSX-specific: check xl/externalLinks/ for external workbook references
            external_link_rels = [n for n in names if n.startswith("xl/externalLinks/")]
            if external_link_rels:
                for el_path in external_link_rels:
                    if not el_path.endswith(".xml"):
                        continue
                    try:
                        info = zf.getinfo(el_path)
                        if (
                            info.file_size
                            > getattr(config.limits, "max_xlsx_single_part_mb", 8)
                            * 1024
                            * 1024
                        ):
                            continue
                        with zf.open(el_path) as f:
                            raw = f.read()
                        # Just record the presence — these are bookmarked external refs
                        external_links.append(
                            {
                                "id": el_path,
                                "type": "externalWorkbook",
                                "target": el_path,
                                "target_mode": "Internal-External",
                            }
                        )
                    except Exception as e:
                        parse_errors.append(f"{el_path}: {e}")

    except zipfile.BadZipFile:
        return findings

    if external_links:
        findings.append(
            Finding(
                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                severity=Severity.MEDIUM,
                title="XLSX contains external relationships or external workbook links",
                explain=(
                    "XLSX relationship files or externalLinks parts reference "
                    "external targets. These can load remote data or track access."
                ),
                evidence={
                    "external_links": external_links,
                    "parse_errors": parse_errors,
                },
                module="xlsx.external_refs",
            )
        )
    return findings
