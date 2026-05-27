from __future__ import annotations
import re
import zipfile
from typing import List

from ...enums import ThreatID, Severity, VerdictClass
from ...report import Finding
from ...config import ScanConfig
from ...logger import get_logger

logger = get_logger()



STEALTH_CHARS = [
    (b"\xe2\x80\x8b", "Zero Width Space"),
    (b"\xe2\x80\xae", "Right-to-Left Override"),
]

# ── ATS manipulation stuffing patterns (T9) ──────────────────────────────
# Fallback used when config.ats_stuffing_patterns_bytes is unavailable
# (e.g. older ScanConfig instances).  The canonical list lives in ScanConfig
# so operators can extend or suppress entries without editing source.
_ATS_STUFFING_PATTERNS_BYTES: list[bytes] = [
    b"ignore scoring rubric",
    b"top candidate top candidate top candidate",
    b"hidden ats text",
    b"bypass ats",
    b"ats bypass",
]

# ── Hidden content patterns (H1 parity for XLSX) ──────────────────────────
# 1. Near-white cell color in xl/styles.xml: ARGB "FF" + RGB ∈ [EF]{6}
#    R,G,B ≥ 0xEE (238/255) = invisible on white sheet.
_XLSX_WHITE_COLOR_RE = re.compile(
    rb'<color\s+rgb="FF([EF]{6})"', re.IGNORECASE
)
# 2. Hide-all custom number format ";;;" — renders no value for any cell type
_XLSX_HIDE_ALL_RE = re.compile(rb'formatCode=";;;"', re.IGNORECASE)
# 3. Hidden rows / columns in worksheet XML
_XLSX_HIDDEN_ROW_RE = re.compile(rb'<row\b[^>]+\bhidden="1"')
_XLSX_HIDDEN_COL_RE = re.compile(rb'<col\b[^>]+\bhidden="1"')


def _check_hidden_xlsx_styles(content: bytes) -> list[tuple[str, str]]:
    """Detect hidden-text techniques in xl/styles.xml bytes."""
    hits: list[tuple[str, str]] = []
    m = _XLSX_WHITE_COLOR_RE.search(content)
    if m:
        hits.append(("white_color", f"near-white cell color: #{m.group(1).decode()}"))
    if _XLSX_HIDE_ALL_RE.search(content):
        hits.append(("hide_all_format", 'hide-all number format ";;;" found'))
    return hits


# D.8: XLM (Excel 4.0 macro) execution primitives. These run as formulas
# regardless of whether the sheet is declared a macrosheet — auto_open ranges
# can point at an ordinary worksheet that contains EXEC() / CALL().
_XLM_PRIMITIVES_RE = re.compile(
    rb"=(?:EXEC|CALL|REGISTER|RUN|FORMULA\.FILL|ALERT|ARGUMENT|DOCUMENTS)\(",
    re.IGNORECASE,
)
# D.8: hidden / veryHidden sheet declarations in xl/workbook.xml.
_HIDDEN_SHEET_RE = re.compile(
    rb'<sheet\b[^>]*\bstate\s*=\s*"(hidden|veryHidden)"', re.IGNORECASE
)


def fast_scan_xlsx(file_path: str, config: ScanConfig) -> List[Finding]:
    """Fast structural scan of an XLSX (ZIP-based) file."""
    findings: List[Finding] = []

    if not zipfile.is_zipfile(file_path):
        return findings

    # D.8: track veryHidden sheets so we can promote XLM findings to CRITICAL
    # when a veryHidden sheet co-occurs with XLM execution primitives in any
    # worksheet XML.
    very_hidden_sheets: list[str] = []
    hidden_sheets: list[str] = []

    with zipfile.ZipFile(file_path, "r") as zf:
        infolist = zf.infolist()
        part_count = len(infolist)
        total_uncompressed = sum(z.file_size for z in infolist)
        total_compressed = sum(z.compress_size for z in infolist)
        overall_ratio = (
            total_uncompressed / total_compressed if total_compressed > 0 else 0
        )

        # 1. DoS / structure checks
        if part_count > config.limits.max_xlsx_parts:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="Too many XLSX parts",
                    explain=(
                        f"File contains {part_count} parts "
                        f"(limit {config.limits.max_xlsx_parts})."
                    ),
                    evidence={
                        "part_count": part_count,
                        "limit": config.limits.max_xlsx_parts,
                    },
                    module="fast_scan.xlsx.structure",
                )
            )

        total_mb = total_uncompressed / (1024 * 1024)
        if total_mb > config.limits.max_xlsx_total_uncompressed_mb:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="XLSX total uncompressed size too large",
                    explain=(
                        f"Uncompressed size {total_mb:.2f} MB exceeds limit "
                        f"{config.limits.max_xlsx_total_uncompressed_mb} MB."
                    ),
                    evidence={"size_mb": total_mb},
                    module="fast_scan.xlsx.structure",
                )
            )

        sheet_count = sum(
            1
            for z in infolist
            if z.filename.startswith("xl/worksheets/sheet")
            and z.filename.endswith(".xml")
        )
        if sheet_count > config.limits.max_pages:
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.MEDIUM,
                    title="Excessive worksheet count",
                    explain=(
                        f"Workbook contains {sheet_count} sheets "
                        f"(limit {config.limits.max_pages})."
                    ),
                    evidence={"sheet_count": sheet_count},
                    module="fast_scan.xlsx.structure",
                )
            )

        suspicious_parts = 0

        # D.8: detect veryHidden / hidden worksheet declarations.  veryHidden
        # sheets are not unhideable from the Excel UI and are a standard XLM
        # hiding technique (Pikabot, IcedID).
        for z in infolist:
            if z.filename == "xl/workbook.xml":
                try:
                    with zf.open(z) as wbf:
                        wb_bytes = wbf.read(256 * 1024)
                    for state_match in _HIDDEN_SHEET_RE.finditer(wb_bytes):
                        state = state_match.group(1).decode("ascii", errors="ignore")
                        # Capture the sheet name if available within ±200 bytes
                        ctx_start = max(0, state_match.start() - 200)
                        ctx = wb_bytes[ctx_start: state_match.end() + 50]
                        name_m = re.search(rb'\bname\s*=\s*"([^"]+)"', ctx)
                        sheet_name = (
                            name_m.group(1).decode("utf-8", errors="ignore")
                            if name_m else "unknown"
                        )
                        if state == "veryHidden":
                            very_hidden_sheets.append(sheet_name)
                        else:
                            hidden_sheets.append(sheet_name)
                    if very_hidden_sheets:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title="Excel Very-Hidden Worksheet",
                                explain=(
                                    f"Workbook contains {len(very_hidden_sheets)} "
                                    'sheet(s) declared state="veryHidden": '
                                    f"{very_hidden_sheets[:5]}. veryHidden sheets "
                                    "cannot be unhidden from the Excel UI and are "
                                    "a known XLM macro hiding technique."
                                ),
                                evidence={
                                    "subtype": "very_hidden_sheet",
                                    "sheets": very_hidden_sheets[:10],
                                    "count": len(very_hidden_sheets),
                                    "malicious_text": ", ".join(very_hidden_sheets[:3]),
                                },
                                confidence=0.85,
                                module="fast_scan.xlsx.hidden_sheet",
                            )
                        )
                except Exception:
                    pass
                break  # workbook.xml is unique

        # 2. Per-part checks
        for z in infolist:
            # Large individual part
            if z.file_size > config.limits.max_xlsx_single_part_mb * 1024 * 1024:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Large individual XLSX part",
                        explain=(
                            f"Part {z.filename} is {z.file_size / 1024 / 1024:.2f} MB."
                        ),
                        evidence={
                            "filename": z.filename,
                            "size_mb": z.file_size / 1024 / 1024,
                        },
                        module="fast_scan.xlsx.structure",
                    )
                )

            # Compression ratio (zip bomb heuristic)
            ratio = z.file_size / z.compress_size if z.compress_size > 0 else 0
            if (
                ratio > getattr(config.limits, "max_docx_overall_expansion_ratio", 200)
                and z.file_size > 1024 * 1024
            ):
                suspicious_parts += 1

            # VBA macros (xlsm / xls files with macro support)
            if z.filename.endswith("vbaProject.bin") or "macrosheets" in z.filename:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T2_ACTIVE_CONTENT,
                        severity=Severity.HIGH,
                        title="XLSX contains VBA macro project",
                        explain=(
                            f"Found '{z.filename}' indicating macro-enabled content. "
                            "Macros in spreadsheets are a critical active-content risk."
                        ),
                        evidence={"filename": z.filename},
                        module="fast_scan.xlsx.macros",
                    )
                )
                # D.1: scan vbaProject.bin for stomping + shell APIs
                if (
                    z.filename.endswith("vbaProject.bin")
                    and getattr(config, "enable_legacy_office", True)
                ):
                    try:
                        from ..ole.fast_scan import scan_embedded_vbaproject
                        findings.extend(
                            scan_embedded_vbaproject(zf, z.filename, config)
                        )
                    except Exception as _vba_e:
                        logger.debug("vbaProject scan failed: %s", _vba_e)

            # Embedded objects
            if z.filename.startswith("xl/embeddings/"):
                if z.file_size > config.limits.min_embedded_object_size_bytes:
                    evidence = {"filename": z.filename, "size": z.file_size}
                    severity = Severity.MEDIUM
                    title = "XLSX embedded object found"
                    explain = f"Found embedded object '{z.filename}'."
                    try:
                        with zf.open(z.filename) as emf:
                            header = emf.read(4096)
                            if header.startswith(b"\xD0\xCF\x11\xE0"):
                                severity = Severity.HIGH
                                title = "Malicious OLE Payload Signature"
                                explain += " Contains OLE binary header."
                            elif header.startswith(b"MZ"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains DOS MZ header."
                            elif header.startswith(b"\x7FELF"):
                                severity = Severity.CRITICAL
                                title = "Executable Payload Signature"
                                explain += " Contains ELF binary header."
                    except Exception:
                        pass

                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=severity,
                            title=title,
                            explain=explain,
                            evidence=evidence,
                            confidence=0.75,
                            module="fast_scan.xlsx.ole",
                            # MZ (PE) or ELF magic in an embedded object is
                            # definitive — no legitimate document needs to
                            # embed a Windows or Linux executable. OLE alone
                            # stays REVIEW (could be a benign Equation or
                            # ChartObject); only MZ/ELF flips to BLOCK.
                            verdict_class=(
                                VerdictClass.BLOCK
                                if severity == Severity.CRITICAL
                                else VerdictClass.REVIEW
                            ),
                        )
                    )

            # B.10: Power Query / external data connections — xl/connections.xml,
            # xl/queryTables/, xl/externalLinks/ fetch remote data on open.
            if (
                z.filename == "xl/connections.xml"
                or z.filename.startswith("xl/queryTables/")
                or z.filename.startswith("xl/externalLinks/")
            ):
                try:
                    with zf.open(z) as f:
                        conn_content = f.read(64 * 1024)
                    _HTTP_RE = re.compile(rb"https?://[^\s\"'<]{8,}", re.IGNORECASE)
                    _http_m = _HTTP_RE.search(conn_content)
                    if _http_m:
                        url = _http_m.group(0)[:120].decode("ascii", errors="replace")
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                severity=Severity.HIGH,
                                title="XLSX External Data Connection / Power Query",
                                explain=(
                                    f"Outbound URL in {z.filename}: '{url}'. "
                                    "Excel Power Query and external connections fetch "
                                    "remote data on workbook open — a data-exfiltration "
                                    "and remote-code-execution vector."
                                ),
                                evidence={"filename": z.filename, "url": url},
                                confidence=0.85,
                                module="fast_scan.xlsx.powerquery",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                severity=Severity.MEDIUM,
                                title="XLSX External Data Connection Part",
                                explain=(
                                    f"Workbook contains {z.filename}, indicating "
                                    "Power Query or external data links that can "
                                    "fetch remote content on open."
                                ),
                                evidence={"filename": z.filename},
                                confidence=0.75,
                                module="fast_scan.xlsx.powerquery",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # External relationships
            if z.filename.endswith(".rels"):
                try:
                    with zf.open(z) as f:
                        rel_content = f.read(512 * 1024)
                        if b'TargetMode="External"' in rel_content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                    severity=Severity.MEDIUM,
                                    title="XLSX external relationship found",
                                    explain=(
                                        f"Found 'TargetMode=\"External\"' in "
                                        f"{z.filename}, indicating external content."
                                    ),
                                    evidence={"filename": z.filename},
                                    confidence=0.65,
                                    module="fast_scan.xlsx.rels",
                                )
                            )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

            # Hidden content in styles (white-color cells, hide-all number format)
            if z.filename == "xl/styles.xml":
                try:
                    with zf.open(z) as f:
                        styles_content = f.read(512 * 1024)
                    for technique, detail in _check_hidden_xlsx_styles(styles_content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title=f"XLSX Hidden Text Technique ({technique})",
                                explain=(
                                    f"Detected {detail} in xl/styles.xml. "
                                    "Cell content styled to be invisible to human "
                                    "readers but present in the data stream."
                                ),
                                evidence={"technique": technique, "detail": detail},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading xl/styles.xml: %s", e)

            # Formula / DDE injection — scan worksheet XML for =,+,-,@ starts
            # Also keyword scan in sheet content
            if z.filename.startswith("xl/worksheets/sheet") and z.filename.endswith(
                ".xml"
            ):
                try:
                    with zf.open(z) as f:
                        content = f.read(1024 * 1024)  # 1 MB cap
                    content_lower = content.lower()

                    # ATS manipulation stuffing patterns — list is config-driven
                    # so operators can extend or suppress without editing source.
                    _ats_patterns = getattr(
                        config, "ats_stuffing_patterns_bytes", _ATS_STUFFING_PATTERNS_BYTES
                    )
                    for _ats_pat in _ats_patterns:
                        if _ats_pat in content_lower:
                            _pat_str = _ats_pat.decode("ascii", errors="replace")
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T9_ATS_MANIPULATION,
                                    severity=Severity.HIGH,
                                    title="ATS Manipulation Pattern (XLSX fast scan)",
                                    explain=(
                                        f"Found ATS manipulation keyword "
                                        f"'{_pat_str}' in {z.filename}. "
                                        "Adversarial phrase injected to manipulate ATS scoring."
                                    ),
                                    evidence={
                                        "pattern": _pat_str,
                                        "part": z.filename,
                                        "malicious_text": _pat_str,
                                    },
                                    confidence=0.85,
                                    module="fast_scan.xlsx.ats",
                                )
                            )
                            break  # one T9 finding per sheet

                    # D.8: XLM (Excel 4.0 macro) execution primitives in any
                    # worksheet XML — even an ordinary sheet may host these
                    # when auto_open names point at it.  Critical when
                    # co-located with a veryHidden sheet declaration.
                    xlm_match = _XLM_PRIMITIVES_RE.search(content)
                    if xlm_match:
                        xlm_sev = (
                            Severity.CRITICAL if very_hidden_sheets else Severity.HIGH
                        )
                        primitive = xlm_match.group(0).decode(
                            "ascii", errors="replace"
                        )
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T1_MALWARE if very_hidden_sheets
                                else ThreatID.T2_ACTIVE_CONTENT,
                                severity=xlm_sev,
                                title="Excel XLM Macro Primitive in Worksheet",
                                explain=(
                                    f"Worksheet {z.filename} contains XLM "
                                    f"primitive '{primitive}'. XLM (Excel 4.0) "
                                    "macros execute as formulas; common droppers "
                                    "(Pikabot, IcedID, Qakbot) hide them in "
                                    "veryHidden sheets."
                                    + (
                                        " Workbook also declares veryHidden "
                                        "sheets — high-confidence dropper pattern."
                                        if very_hidden_sheets else ""
                                    )
                                ),
                                evidence={
                                    "subtype": "inline_xlm",
                                    "primitive": primitive,
                                    "part": z.filename,
                                    "very_hidden_present": bool(very_hidden_sheets),
                                    "malicious_text": primitive,
                                },
                                confidence=0.95 if very_hidden_sheets else 0.85,
                                module="fast_scan.xlsx.xlm",
                                mitre_technique="T1059.005",
                                # Inline XLM with a veryHidden sheet is the
                                # exact dropper pattern (Pikabot/IcedID/Qakbot)
                                # — definitive. Bare XLM without veryHidden
                                # could be a legit Excel 4 workbook (rare but
                                # possible) — stays REVIEW.
                                verdict_class=(
                                    VerdictClass.BLOCK
                                    if very_hidden_sheets
                                    else VerdictClass.REVIEW
                                ),
                            )
                        )

                    # B.10: WEBSERVICE / FILTERXML formulas make outbound HTTP calls
                    if b"webservice(" in content_lower or b"filterxml(" in content_lower:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                severity=Severity.HIGH,
                                title="XLSX WEBSERVICE/FILTERXML Formula (HTTP Exfiltration)",
                                explain=(
                                    f"Found WEBSERVICE() or FILTERXML() formula in "
                                    f"{z.filename}. These Excel functions make outbound "
                                    "HTTP requests on recalculation — a data-exfiltration vector."
                                ),
                                evidence={"part": z.filename},
                                confidence=0.85,
                                module="fast_scan.xlsx.powerquery",
                            )
                        )

                    # DDE injection heuristic: =DDE( or =CMD patterns
                    if b"=dde(" in content_lower or b"=cmd|" in content_lower:
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T9_ATS_MANIPULATION,
                                severity=Severity.HIGH,
                                title="Potential DDE injection in XLSX",
                                explain=(
                                    f"Found DDE formula pattern in {z.filename}. "
                                    "This can be used for ATS manipulation."
                                ),
                                evidence={"part": z.filename},
                                module="fast_scan.xlsx.dde",
                            )
                        )
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T2_ACTIVE_CONTENT,
                                severity=Severity.HIGH,
                                title="Potential DDE injection in XLSX",
                                explain=(
                                    f"Found DDE formula pattern in {z.filename}. "
                                    "DDE formulas can execute arbitrary commands."
                                ),
                                evidence={"filename": z.filename},
                                module="fast_scan.xlsx.dde",
                            )
                        )
                    for kw in config.prompt_injection_keywords_bytes:
                        if kw in content_lower:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T4_PROMPT_INJECTION,
                                    severity=Severity.MEDIUM,
                                    title="Potential injection keyword (XLSX fast scan)",
                                    explain=(
                                        f"Found keyword '{kw.decode('ascii')}' "
                                        f"in {z.filename}."
                                    ),
                                    evidence={
                                        "keyword": kw.decode("ascii"),
                                        "part": z.filename,
                                    },
                                    confidence=0.65,
                                    module="fast_scan.xlsx.keywords",
                                )
                            )

                    for char_bytes, name in STEALTH_CHARS:
                        if char_bytes in content:
                            findings.append(
                                Finding(
                                    threat_id=ThreatID.T3_OBFUSCATION,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious hidden character ({name}) in XLSX",
                                    explain=(
                                        f"Found {name} in {z.filename}, "
                                        "possible stealth injection."
                                    ),
                                    evidence={"char": name, "part": z.filename},
                                    module="fast_scan.xlsx.stealth",
                                )
                            )

                    # H1 parity: hidden rows / columns
                    if _XLSX_HIDDEN_ROW_RE.search(content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title="XLSX Hidden Rows Detected",
                                explain=(
                                    f"Worksheet {z.filename} contains rows with "
                                    'hidden="1" — content invisible to the user '
                                    "but readable by parsers and ATS systems."
                                ),
                                evidence={"part": z.filename, "technique": "hidden_row"},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                    if _XLSX_HIDDEN_COL_RE.search(content):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T3_OBFUSCATION,
                                severity=Severity.HIGH,
                                title="XLSX Hidden Columns Detected",
                                explain=(
                                    f"Worksheet {z.filename} contains columns with "
                                    'hidden="1" — content invisible to the user '
                                    "but readable by parsers and ATS systems."
                                ),
                                evidence={"part": z.filename, "technique": "hidden_col"},
                                confidence=0.90,
                                module="fast_scan.xlsx.hidden_text",
                            )
                        )
                except Exception as e:
                    logger.debug("Error reading %s: %s", z.filename, e)

        # Zip bomb aggregate check
        if suspicious_parts >= 2 or (
            overall_ratio > config.limits.max_docx_overall_expansion_ratio
            and total_mb > 10
        ):
            findings.append(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="XLSX suspicious compression ratio",
                    explain=(
                        "High compression ratio detected, characteristic of zip "
                        "bombs or generated obfuscation."
                    ),
                    evidence={
                        "overall_ratio": round(overall_ratio, 2),
                        "suspicious_parts": suspicious_parts,
                    },
                    module="fast_scan.xlsx.structure",
                )
            )

    return findings
