"""E.2 — OpenDocument Format (ODT / ODS / ODP) fast scanner.

ODF files are ZIP archives with a fixed part structure:
  • content.xml       — body
  • meta.xml          — Dublin Core + ODF metadata
  • settings.xml      — application settings (may contain external URLs)
  • styles.xml        — styles + hidden-text styling
  • Scripts/          — Basic / Python / JavaScript macro modules
  • Pictures/         — embedded images
  • manifest.rdf      — RDF manifest

Detects:
  T1   Macro presence (Scripts/ entries) — HIGH; CVE-2023-2255 `macro:` URI
       pattern in content.xml — CRITICAL.
  T2   External references in settings.xml / content.xml (remote templates,
       data sources).
  T4   Prompt injection keywords in content.xml / meta.xml.
  T6   Zip-bomb structure checks (parts, total uncompressed size).
"""
from __future__ import annotations

import re
import zipfile
from typing import List

from ...config import ScanConfig
from ...enums import ThreatID, Severity, VerdictClass
from ...report import Finding
from ...logger import get_logger

logger = get_logger()


# CVE-2023-2255: LibreOffice `macro:///Library.Module.Function` URI in a
# document link auto-executes when the user clicks the hyperlink.
_MACRO_URI_RE = re.compile(
    rb"(?:xlink:href|href)\s*=\s*[\"']macro:[^\"'>]+", re.IGNORECASE,
)

_EXTERNAL_HTTP_RE = re.compile(
    rb"(?:xlink:href|href|table:source-name|"
    rb"text:reference-ref)\s*=\s*[\"']https?://[^\"'>]+",
    re.IGNORECASE,
)

# Hidden text styling in ODF: display="none", color="#FFFFFF" with white bg,
# fo:font-size of zero/near-zero.
_HIDDEN_DISPLAY_RE = re.compile(rb'text:display\s*=\s*"none"')
_WHITE_TEXT_RE = re.compile(rb'fo:color\s*=\s*"#[Ff][EeFf][EeFf][EeFf][EeFf][EeFf]"')
_ZERO_FONT_RE = re.compile(rb'fo:font-size\s*=\s*"0(?:\.\d+)?(?:pt|px|cm|in)?"')


def fast_scan_odf(file_path: str, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []

    if not zipfile.is_zipfile(file_path):
        return findings

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infolist = zf.infolist()
            part_count = len(infolist)
            total_uncompressed = sum(z.file_size for z in infolist)
            total_compressed = sum(z.compress_size for z in infolist)
            overall_ratio = (
                total_uncompressed / total_compressed if total_compressed > 0 else 0
            )

            # T6: structure DoS
            if part_count > config.limits.max_pptx_parts:
                findings.append(Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many ODF parts",
                    explain=f"ODF file contains {part_count} parts (limit "
                            f"{config.limits.max_pptx_parts}).",
                    evidence={"part_count": part_count,
                              "malicious_text": f"{part_count} parts"},
                    confidence=0.85,
                    module="fast_scan.odf.structure",
                ))
                return findings

            total_mb = total_uncompressed / (1024 * 1024)
            if total_mb > config.limits.max_pptx_total_uncompressed_mb:
                findings.append(Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="ODF total uncompressed size too large",
                    explain=f"Uncompressed size {total_mb:.1f} MB exceeds "
                            f"{config.limits.max_pptx_total_uncompressed_mb} MB.",
                    evidence={"size_mb": total_mb,
                              "malicious_text": f"{total_mb:.1f} MB"},
                    confidence=0.85,
                    module="fast_scan.odf.structure",
                ))
                return findings

            has_scripts = False
            for z in infolist:
                fname = z.filename

                # T1: macro presence (Scripts/ folder)
                if fname.startswith("Scripts/") and not fname.endswith("/"):
                    has_scripts = True

                # ── content.xml — the body part ──────────────────────────
                if fname == "content.xml":
                    try:
                        with zf.open(z) as f:
                            content = f.read(2 * 1024 * 1024)  # 2 MB cap
                    except Exception:
                        continue
                    _scan_content_xml(content, findings, config)

                # ── meta.xml — metadata fields ──────────────────────────
                elif fname == "meta.xml":
                    try:
                        with zf.open(z) as f:
                            meta = f.read(128 * 1024)
                    except Exception:
                        continue
                    meta_lower = meta.lower()
                    for kw in config.prompt_injection_keywords_bytes:
                        if kw in meta_lower:
                            findings.append(Finding(
                                threat_id=ThreatID.T8_METADATA_INJECTION,
                                severity=Severity.MEDIUM,
                                title="Prompt Injection in ODF meta.xml",
                                explain=(
                                    f"Injection keyword "
                                    f"'{kw.decode('ascii', errors='replace')}' "
                                    "found in meta.xml — extracted by ODF parsers "
                                    "and LLM document loaders."
                                ),
                                evidence={
                                    "subtype": "odf_meta_injection",
                                    "keyword": kw.decode("ascii", errors="replace"),
                                    "malicious_text": kw.decode("ascii", errors="replace"),
                                },
                                confidence=0.75,
                                module="fast_scan.odf.meta",
                            ))
                            break

                # ── settings.xml — application + external refs ─────────
                elif fname == "settings.xml":
                    try:
                        with zf.open(z) as f:
                            settings = f.read(128 * 1024)
                    except Exception:
                        continue
                    if _EXTERNAL_HTTP_RE.search(settings):
                        m = _EXTERNAL_HTTP_RE.search(settings)
                        url = m.group(0)[:120].decode("ascii", errors="replace") if m else ""
                        findings.append(Finding(
                            threat_id=ThreatID.T2_ACTIVE_CONTENT,
                            severity=Severity.MEDIUM,
                            title="ODF External Reference in settings.xml",
                            explain=(
                                f"settings.xml references external URL "
                                f"('{url}'). May fetch remote template or "
                                "external content on open."
                            ),
                            evidence={
                                "subtype": "odf_external_settings",
                                "url": url,
                                "malicious_text": url,
                            },
                            confidence=0.75,
                            module="fast_scan.odf.settings",
                        ))

                # ── styles.xml — hidden text styling ───────────────────
                elif fname == "styles.xml":
                    try:
                        with zf.open(z) as f:
                            styles = f.read(256 * 1024)
                    except Exception:
                        continue
                    hits = []
                    if _HIDDEN_DISPLAY_RE.search(styles):
                        hits.append("display:none")
                    if _WHITE_TEXT_RE.search(styles):
                        hits.append("near-white text color")
                    if _ZERO_FONT_RE.search(styles):
                        hits.append("zero-size font")
                    if hits:
                        findings.append(Finding(
                            threat_id=ThreatID.T3_OBFUSCATION,
                            severity=Severity.HIGH,
                            title="ODF Hidden-Text Styling in styles.xml",
                            explain=(
                                f"styles.xml uses {', '.join(hits)} — content "
                                "styled to be invisible to readers but extracted "
                                "by parsers and ATS systems."
                            ),
                            evidence={
                                "subtype": "odf_hidden_styles",
                                "techniques": hits,
                                "malicious_text": ", ".join(hits),
                            },
                            confidence=0.85,
                            module="fast_scan.odf.hidden",
                        ))

            if has_scripts:
                findings.append(Finding(
                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                    severity=Severity.HIGH,
                    title="ODF Macro Scripts Present",
                    explain=(
                        "Document contains entries under Scripts/ — Basic / "
                        "Python / JavaScript macros that execute on open."
                    ),
                    evidence={
                        "subtype": "odf_macros",
                        "malicious_text": "Scripts/ directory present",
                    },
                    confidence=0.85,
                    module="fast_scan.odf.macros",
                    mitre_technique="T1137.001",
                ))

            # Zip bomb aggregate
            if overall_ratio > 200 and total_mb > 10:
                findings.append(Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="ODF Suspicious Compression Ratio",
                    explain=f"Compression ratio {overall_ratio:.0f}x — "
                            "zip-bomb pattern.",
                    evidence={"overall_ratio": round(overall_ratio, 2)},
                    confidence=0.85,
                    module="fast_scan.odf.structure",
                ))

    except Exception as exc:
        logger.debug("ODF fast scan error: %s", exc)

    return findings


def _scan_content_xml(content: bytes, findings: list[Finding], config: ScanConfig) -> None:
    """Apply T2 / T4 patterns to content.xml bytes."""
    # CVE-2023-2255: macro:// URI in a hyperlink
    macro_m = _MACRO_URI_RE.search(content)
    if macro_m:
        target = macro_m.group(0)[:150].decode("ascii", errors="replace")
        findings.append(Finding(
            threat_id=ThreatID.T1_MALWARE,
            severity=Severity.CRITICAL,
            title="ODF macro:// URI (CVE-2023-2255)",
            explain=(
                f"content.xml contains a macro:// URI ('{target}') — "
                "CVE-2023-2255: LibreOffice auto-executes macro URIs on "
                "hyperlink click."
            ),
            evidence={
                "subtype": "odf_macro_uri",
                "target": target,
                "malicious_text": target,
            },
            confidence=0.95,
            module="fast_scan.odf.macro_uri",
            cve="CVE-2023-2255",
            mitre_technique="T1203",
            # Definitive RCE vector — no legitimate document needs a
            # macro:// URI in a hyperlink; always BLOCK.
            verdict_class=VerdictClass.BLOCK,
        ))

    # T2: external hyperlinks
    ext_m = _EXTERNAL_HTTP_RE.search(content)
    if ext_m:
        url = ext_m.group(0)[:120].decode("ascii", errors="replace")
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.LOW,
            title="ODF External URL in content.xml",
            explain=(
                f"content.xml contains an external URL reference "
                f"('{url}'). Informational; many legitimate documents "
                "include URLs."
            ),
            evidence={
                "subtype": "odf_external_url",
                "url": url,
                "malicious_text": url,
            },
            confidence=0.55,
            module="fast_scan.odf.external",
        ))

    # T4: prompt injection keyword scan on the body
    content_lower = content.lower()
    seen_kws: set[bytes] = set()
    for kw in config.prompt_injection_keywords_bytes:
        if kw in content_lower and kw not in seen_kws:
            seen_kws.add(kw)
            findings.append(Finding(
                threat_id=ThreatID.T4_PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                title="Potential Prompt Injection in ODF content.xml",
                explain=(
                    f"Injection keyword '{kw.decode('ascii', errors='replace')}' "
                    "in content.xml. Deep scan confirms via the full T4 pipeline."
                ),
                evidence={
                    "subtype": "odf_content_keyword",
                    "keyword": kw.decode("ascii", errors="replace"),
                    "malicious_text": kw.decode("ascii", errors="replace"),
                },
                confidence=0.65,
                module="fast_scan.odf.keywords",
            ))
            if len(seen_kws) >= 3:
                break
