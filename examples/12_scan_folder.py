#!/usr/bin/env python3
"""Scan a folder of documents and write flat CSV plus API-style JSON reports."""

from __future__ import annotations

import argparse
import csv
import enum
import json
import shutil
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

VALID_PROFILES = {"lenient", "balanced", "strict"}


def build_scan_config(config_cls: type, profile: str, mode: str, enable_pii: bool = True) -> Any:
    # `profile` selects the threshold/ML preset (lenient|balanced|strict).
    # `mode` is an example-local switch that only toggles antivirus.
    if profile not in VALID_PROFILES:
        profile = "strict"
    return config_cls(
        profile=profile,
        enable_antivirus=(mode == "aggressive"),
        enable_pii_checks=enable_pii,
    )


FIELDNAMES = [
    "Filename",
    "scan_mode",
    "verdict",
    "risk_score",
    "finding_count",
    "detected_threats",
    "threat_id",
    "title",
    "severity",
    "verdict_class",
    "module",
    "confidence",
    "description",
    "technical_detail",
    "malicious_text",
    "hidden_text",
    "evidence_json",
    "location",
    "cve",
    "mitre_technique",
    "attack_objective",
    "error",
]


def iter_files(input_dir: Path, exclude_dir: Path | None = None) -> Iterable[Path]:
    exclude = exclude_dir.resolve() if exclude_dir else None
    for path in sorted(input_dir.rglob("*")):
        if not (path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS):
            continue
        # Don't rescan files we previously sorted into the output tree.
        if exclude and exclude in path.resolve().parents:
            continue
        yield path


# Maps a scan verdict to a destination bucket. Anything not listed here
# (REVIEW, FLAG, WARN, UNKNOWN, ...) falls through to "suspicious".
VERDICT_BUCKETS = {
    "ERROR": "error",
    "BLOCK": "blocked",
    "BLOCKED": "blocked",
    "ALLOW": "clean",
    "CLEAN": "clean",
    "PASS": "clean",
}


def bucket_for_verdict(verdict: Any) -> str:
    return VERDICT_BUCKETS.get(str(verdict).upper(), "suspicious")


def sort_file(file_path: Path, base_dir: Path, sorted_dir: Path, verdict: Any) -> str:
    """Copy file_path into sorted_dir/<bucket>/<relative path>; return the bucket."""
    bucket = bucket_for_verdict(verdict)
    dest = sorted_dir / bucket / file_path.relative_to(base_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, dest)
    return bucket


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


def _evidence_value(finding: dict[str, Any], key: str) -> str:
    ev = finding.get("evidence")
    if isinstance(ev, dict):
        return text_from(ev.get(key))
    return ""


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
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    evidence_json = json.dumps(evidence, ensure_ascii=False, default=str, sort_keys=True) if evidence else ""
    return {
        "Filename": filename,
        "scan_mode": scan_mode,
        "verdict": verdict,
        "risk_score": round(risk_score, 4),
        "finding_count": finding_count,
        "detected_threats": threats,
        "threat_id": text_from(finding.get("threat_id") or finding.get("threat") or finding.get("id")),
        "title": text_from(finding.get("title")),
        "severity": text_from(finding.get("severity")),
        "verdict_class": text_from(finding.get("verdict_class")),
        "module": text_from(finding.get("module")),
        "confidence": text_from(finding.get("confidence")),
        "description": finding_description(finding),
        "technical_detail": text_from(finding.get("technical_detail")),
        "malicious_text": _evidence_value(finding, "malicious_text") or text_from(finding.get("malicious_text")),
        "hidden_text": _evidence_value(finding, "hidden_text"),
        "evidence_json": evidence_json,
        "location": text_from(finding.get("location")),
        "cve": text_from(finding.get("cve")),
        "mitre_technique": text_from(finding.get("mitre_technique")),
        "attack_objective": text_from(finding.get("attack_objective")),
        "error": error,
    }


def json_finding(finding: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "threat_id": text_from(finding.get("threat_id") or finding.get("threat") or finding.get("id")),
        "title": text_from(finding.get("title")),
        "severity": text_from(finding.get("severity")),
        "verdict_class": text_from(finding.get("verdict_class")),
        "module": text_from(finding.get("module")),
        "confidence": finding.get("confidence"),
        "description": finding_description(finding),
        "technical_detail": text_from(finding.get("technical_detail")),
        "cve": text_from(finding.get("cve")),
        "mitre_technique": text_from(finding.get("mitre_technique")),
        "attack_objective": text_from(finding.get("attack_objective")),
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
    parser.add_argument(
        "--sorted-dir",
        type=Path,
        default=None,
        help="Where to copy files into clean/suspicious/blocked/error buckets "
        "(default: <out>/sorted). Originals are never modified.",
    )
    parser.add_argument("--profile", default="strict", choices=sorted(VALID_PROFILES))
    parser.add_argument("--mode", default="standard", choices=SCAN_MODES)
    parser.add_argument(
        "--no-pii",
        dest="enable_pii",
        action="store_false",
        help="Skip the T8 PII detector entirely (no phone/email/SSN/etc. findings). "
        "Useful for resume corpora where PII is expected and not a threat.",
    )
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {args.input_dir}")

    try:
        from doc_firewall import ScanConfig, Scanner
    except ImportError as exc:
        raise SystemExit("doc-firewall is not installed. Run `pip install doc-firewall`.") from exc

    try:
        config = build_scan_config(ScanConfig, args.profile, args.mode, enable_pii=args.enable_pii)
    except TypeError as exc:
        raise SystemExit(
            f"Scan mode '{args.mode}' is not supported by this installed doc-firewall package. "
            "Use `pip install \"doc-firewall[ml]\"` for advanced modes or upgrade doc-firewall."
        ) from exc

    sorted_dir = args.sorted_dir or (args.out / "sorted")

    scanner = Scanner(config)
    rows: list[dict[str, Any]] = []
    json_reports: list[dict[str, Any]] = []
    bucket_counts: dict[str, int] = {}
    for file_path in iter_files(args.input_dir, exclude_dir=sorted_dir):
        json_payload, csv_rows = scan_file(scanner, file_path, args.input_dir, args.mode)
        json_reports.append(json_payload)
        rows.extend(csv_rows)

        bucket = sort_file(file_path, args.input_dir, sorted_dir, json_payload.get("verdict"))
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1

    write_reports(rows, json_reports, args.out)
    if bucket_counts:
        summary = ", ".join(f"{count} {bucket}" for bucket, count in sorted(bucket_counts.items()))
        print(f"Copied files into {sorted_dir}: {summary}")
    return 1 if any(row["error"] for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
