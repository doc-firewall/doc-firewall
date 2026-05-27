"""E.1 — CSV / TSV fast scanner.

Detects:
  T2  Formula injection: cells starting with =, +, -, @ (and tab+= / \\r+=)
      that contain function-call syntax like cmd|, WEBSERVICE(, HYPERLINK(,
      DDE etc.
  T2  WEBSERVICE / FILTERXML / IMPORTDATA / IMPORTXML — outbound HTTP via
      Excel formulas.
  T6  Pathological row / column count.

Body-text T4 and T9 checks happen in deep-scan via the standard detector
pipeline once the CSV is parsed by `parse_csv`.
"""
from __future__ import annotations

import csv
import re
from typing import List

from ...config import ScanConfig
from ...enums import ThreatID, Severity, VerdictClass
from ...report import Finding
from ...logger import get_logger

logger = get_logger()


# Cells beginning with these triggers are evaluated as formulas when the
# CSV is opened in Excel / LibreOffice / Google Sheets.
_FORMULA_PREFIXES = ("=", "+", "-", "@")

# Dangerous in-formula identifiers that signal real execution intent.
_DANGEROUS_FN_RE = re.compile(
    r"\b(?:cmd|powershell|WEBSERVICE|FILTERXML|HYPERLINK|"
    r"IMPORTDATA|IMPORTXML|IMPORTFEED|IMPORTHTML|DDE|EXEC|CALL|"
    r"REGISTER|RUN|FORMULA\.FILL|SHELL)\b",
    re.IGNORECASE,
)

# DDE-style triggers: =cmd|'/c calc'!A1, =@SUM(1+1)*cmd|...
_DDE_TRIGGER_RE = re.compile(r"[|!](?:'|\")?(?:cmd|powershell|/c)\b", re.IGNORECASE)

# Outbound URL hint inside a formula
_HTTP_RE = re.compile(r"https?://[^\s'\"<>)]{8,}", re.IGNORECASE)


def _is_likely_csv(data: bytes) -> bool:
    """Cheap content sniff. CSV has no magic bytes; we accept anything that
    has a comma or tab in the first 4 KB. Single-line CSVs (no newline) are
    accepted as long as there's at least one separator."""
    sample = data[:4096]
    try:
        text = sample.decode("utf-8", errors="replace")
    except Exception:
        return False
    return "," in text or "\t" in text or ";" in text


def fast_scan_csv(file_path: str, config: ScanConfig) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with open(file_path, "rb") as fh:
            raw = fh.read(8 * 1024 * 1024)  # cap at 8 MB
    except OSError:
        return findings

    if not _is_likely_csv(raw):
        return findings

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return findings

    # Sniff the delimiter — fall back to comma.
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel

    row_count = 0
    col_count = 0
    formula_hits: list[tuple[int, int, str]] = []  # (row, col, cell)
    webservice_hit = False
    dde_hit = False

    try:
        reader = csv.reader(text.splitlines(), dialect=dialect)
        for row_idx, row in enumerate(reader):
            row_count += 1
            col_count = max(col_count, len(row))
            for col_idx, raw_cell in enumerate(row):
                cell = raw_cell.strip("\t\r\n ")
                if not cell:
                    continue
                # T2: formula prefix
                if cell[:1] in _FORMULA_PREFIXES and _DANGEROUS_FN_RE.search(cell):
                    if len(formula_hits) < 10:
                        formula_hits.append((row_idx, col_idx, cell[:120]))
                # T2: WEBSERVICE / FILTERXML even without prefix (rare)
                if "webservice(" in cell.lower() or "filterxml(" in cell.lower():
                    webservice_hit = True
                # T2: DDE chain
                if _DDE_TRIGGER_RE.search(cell):
                    dde_hit = True
            if row_count > 200_000:
                break  # bomb guard
    except Exception as exc:
        logger.debug("CSV parse error in fast_scan_csv: %s", exc)

    if formula_hits:
        sample = formula_hits[0]
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.HIGH,
            title="CSV Formula Injection",
            explain=(
                f"Found {len(formula_hits)} cell(s) starting with a formula "
                "trigger character (=, +, -, @) and referencing a dangerous "
                "function (cmd, powershell, WEBSERVICE, HYPERLINK, DDE, etc.). "
                "When the CSV is opened in a spreadsheet application, these "
                "cells execute as formulas without macro warning."
            ),
            evidence={
                "subtype": "csv_formula_injection",
                "hit_count": len(formula_hits),
                "first_row": sample[0],
                "first_col": sample[1],
                "first_cell": sample[2],
                "malicious_text": sample[2],
            },
            confidence=0.90,
            module="fast_scan.csv.formula",
            mitre_technique="T1059",
        ))

    if webservice_hit:
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.HIGH,
            title="CSV Outbound Formula (WEBSERVICE / FILTERXML)",
            explain=(
                "CSV contains WEBSERVICE() or FILTERXML() formula. These Excel "
                "functions make outbound HTTP calls on recalculation — a data "
                "exfiltration vector."
            ),
            evidence={"subtype": "csv_webservice", "malicious_text": "WEBSERVICE/FILTERXML"},
            confidence=0.85,
            module="fast_scan.csv.outbound",
        ))

    if dde_hit:
        findings.append(Finding(
            threat_id=ThreatID.T2_ACTIVE_CONTENT,
            severity=Severity.CRITICAL,
            title="CSV DDE / Command-Pipe Injection",
            explain=(
                "Cell contains DDE-style command pipe (e.g. `=cmd|'/c ...'`) — "
                "executes a shell command when the workbook is opened."
            ),
            evidence={"subtype": "csv_dde", "malicious_text": "DDE pipe in cell"},
            confidence=0.95,
            module="fast_scan.csv.dde",
            mitre_technique="T1559.002",
            # Definitive code-execution vector — `=cmd|'/c calc'!A1` shape
            # has no legitimate use case; always BLOCK.
            verdict_class=VerdictClass.BLOCK,
        ))

    # T6: bomb guard
    if row_count > config.limits.max_pages * 10:
        findings.append(Finding(
            threat_id=ThreatID.T6_DOS,
            severity=Severity.MEDIUM,
            title="CSV Excessive Row Count",
            explain=f"CSV has {row_count} rows — well beyond typical document use.",
            evidence={"row_count": row_count, "col_count": col_count},
            confidence=0.70,
            module="fast_scan.csv.dos",
        ))

    return findings
