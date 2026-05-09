#!/usr/bin/env python3
"""Scan a folder of documents and write flat CSV plus API-style JSON reports."""

from __future__ import annotations

import argparse
import csv
import json
import enum
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

# Self-contained configuration since scan_dataset is not part of doc-firewall examples
SCAN_MODES = ["standard", "aggressive"]
SUPPORTED_EXTENSIONS = {
    ".docx", ".docm",
    ".pdf",
    ".pptx", ".pptm",
    ".xlsx", ".xlsm", ".xlsb",
}

def enum_or_value(val: Any) -> Any:
    if isinstance(val, enum.Enum):
        return val.name
    return val

def finding_to_dict(finding: Any) -> dict[str, Any]:
    if is_dataclass(finding):
        return asdict(finding)
    if isinstance(finding, dict):
        return finding
    return getattr(finding, "__dict__", {})

def build_scan_config(config_cls: type, profile: str, mode: str) -> Any:
    # Basic config setup for the example folder scanner
    # In a real environment, you might merge profile/mode logic
    return config_cls(enable_antivirus=(mode == "aggressive"))


FIELDNAMES = [
    "Filename",
    "scan_mode",
    "verdict",
    "risk_score",
    "finding_count",
    "detected_threats",
    "severity",
    "description",
    "malicious_text",
    "location",
    "error",
]


def iter_files(input_dir: Path) -> Iterable[Path]:
    for path in sorted(input_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield path


def text_from(value: Any) -> str:
    if value in {None, ""}:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return enum_or_value(value)


def finding_description(finding: dict[str, Any]) -> str:
    for key in ("description", "explain", "title", "message", "reason"):
        if finding.get(key):
            return text_from(finding[key])
    return ""


def present(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (dict, list, tuple, set)) and not value:
        return False
    return True


def detected_threats(findings: list[dict[str, Any]]) -> str:
    values = sorted(
        {
            text_from(finding.get("threat_id") or finding.get("threat") or finding.get("id"))
            for finding in findings
            if finding.get("threat_id") or finding.get("threat") or finding.get("id")
        }
    )
    return ";".join(values)


def row_for_finding(
    filename: str,
    scan_mode: str,
    verdict: str,
    risk_score: float,
    finding_count: int,
    threats: str,
    finding: dict[str, Any],
    error: str = "",
) -> dict[str, Any]:
    return {
        "Filename": filename,
        "scan_mode": scan_mode,
        "verdict": verdict,
        "risk_score": round(risk_score, 4),
        "finding_count": finding_count,
        "detected_threats": threats,
        "severity": text_from(finding.get("severity")),
        "description": finding_description(finding),
        "malicious_text": text_from(finding.get("evidence", {}).get("malicious_text") if isinstance(finding.get("evidence"), dict) else finding.get("malicious_text")),
        "location": text_from(finding.get("location")),
        "error": error,
    }


def json_finding(finding: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "threat_id": text_from(finding.get("threat_id") or finding.get("threat") or finding.get("id")),
        "severity": text_from(finding.get("severity")),
        "description": finding_description(finding),
    }
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        payload["evidence"] = evidence
    elif evidence not in {None, ""}:
        payload["evidence"] = {"value": text_from(evidence)}

    malicious_text = text_from(finding.get("malicious_text"))
    if malicious_text:
        payload.setdefault("evidence", {})
        if isinstance(payload["evidence"], dict):
            payload["evidence"].setdefault("malicious_text", malicious_text)

    location = text_from(finding.get("location"))
    if location:
        payload["location"] = location
    return {key: value for key, value in payload.items() if present(value)}


def json_report(
    filename: str,
    scan_mode: str,
    verdict: str,
    risk_score: float,
    findings: list[dict[str, Any]],
    error: str = "",
) -> dict[str, Any]:
    payload = {
        "file_name": filename,
        "scan_mode": scan_mode,
        "verdict": verdict,
        "risk_score": round(risk_score, 4),
        "findings": [json_finding(finding) for finding in findings],
    }
    if error:
        payload["error"] = error
    return payload


def scan_file(scanner: Any, file_path: Path, base_dir: Path, scan_mode: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    filename = file_path.relative_to(base_dir).as_posix()
    try:
        report = scanner.scan(str(file_path))
        findings = [finding_to_dict(finding) for finding in getattr(report, "findings", [])]
        verdict = enum_or_value(getattr(report, "verdict", "UNKNOWN"))
        risk_score = float(getattr(report, "risk_score", 0.0) or 0.0)
        finding_count = len(findings)
        threats = detected_threats(findings)

        if not findings:
            json_payload = json_report(filename, scan_mode, verdict, risk_score, [])
            return json_payload, [
                row_for_finding(
                    filename=filename,
                    scan_mode=scan_mode,
                    verdict=verdict,
                    risk_score=risk_score,
                    finding_count=0,
                    threats="",
                    finding={},
                )
            ]

        json_payload = json_report(filename, scan_mode, verdict, risk_score, findings)
        return json_payload, [
            row_for_finding(
                filename=filename,
                scan_mode=scan_mode,
                verdict=verdict,
                risk_score=risk_score,
                finding_count=finding_count,
                threats=threats,
                finding=finding,
            )
            for finding in findings
        ]
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        json_payload = json_report(filename, scan_mode, "ERROR", 0.0, [], error)
        return json_payload, [
            row_for_finding(
                filename=filename,
                scan_mode=scan_mode,
                verdict="ERROR",
                risk_score=0.0,
                finding_count=0,
                threats="",
                finding={},
                error=error,
            )
        ]


def write_reports(rows: list[dict[str, Any]], json_reports: list[dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "folder_scan_report.csv"
    json_path = output_dir / "folder_scan_report.json"

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    json_path.write_text(json.dumps(json_reports, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(rows)} CSV rows to {csv_path}")
    print(f"Wrote {len(json_reports)} JSON file reports to {json_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path, help="Folder containing DOCX, PDF, PPTX, and XLSX files.")
    parser.add_argument("--out", default=Path("reports/folder_scan"), type=Path)
    parser.add_argument("--profile", default="aggressive")
    parser.add_argument("--mode", default="standard", choices=SCAN_MODES)
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {args.input_dir}")

    try:
        from doc_firewall import ScanConfig, Scanner
    except ImportError as exc:
        raise SystemExit("doc-firewall is not installed. Run `pip install doc-firewall`.") from exc

    try:
        config = build_scan_config(ScanConfig, args.profile, args.mode)
    except TypeError as exc:
        raise SystemExit(
            f"Scan mode '{args.mode}' is not supported by this installed doc-firewall package. "
            "Use `pip install \"doc-firewall[ml]\"` for advanced modes or upgrade doc-firewall."
        ) from exc

    scanner = Scanner(config)
    rows: list[dict[str, Any]] = []
    json_reports: list[dict[str, Any]] = []
    for file_path in iter_files(args.input_dir):
        json_payload, csv_rows = scan_file(scanner, file_path, args.input_dir, args.mode)
        json_reports.append(json_payload)
        rows.extend(csv_rows)

    write_reports(rows, json_reports, args.out)
    return 1 if any(row["error"] for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
