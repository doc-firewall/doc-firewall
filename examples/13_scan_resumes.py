#!/usr/bin/env python3
"""
Example 13: Scan a folder (or single file) of resumes.

A resume-focused companion to 12_scan_folder.py. Like that example it sorts
every document into clean / suspicious / blocked / error buckets and writes
flat CSV plus API-style JSON reports — but everything for one run lands in a
single timestamped ``output_<YYYYMMDD_HHMMSS>/`` folder, and the results are
streamed to disk *incrementally* so a long run survives interruptions:

    output_20260619_120000/
    ├── clean/           copies of resumes, bucketed by verdict
    ├── suspicious/
    ├── blocked/
    ├── error/
    ├── resume_scan_report.csv            (header once, rows APPENDED every 10)
    ├── resume_scan_report_001.json       (JSON reports, 100 per file)
    ├── resume_scan_report_002.json
    └── ...

Detection policy is configurable through a YAML file (see resume.yaml), just
like 04_yaml_config_scan.py, so the policy lives next to the data.

Usage:
    python 13_scan_resumes.py <path>                       # uses resume.yaml
    python 13_scan_resumes.py <path> --config my.yaml
    python 13_scan_resumes.py <path> --out reports/resumes --workers 3
    python 13_scan_resumes.py resume.pdf                   # single file works too

<path> may be a single resume or a folder; folders are scanned recursively.
Originals are never modified — only copied into the bucket folders.
"""

from __future__ import annotations

import argparse
import csv
import enum
import json
import shutil
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# Resume corpora are overwhelmingly these formats.
RESUME_EXTENSIONS = {".pdf", ".docx", ".docm", ".doc", ".odt", ".rtf"}

# Default config lives beside this script.
DEFAULT_CONFIG = Path(__file__).resolve().parent / "resume.yaml"

# Incremental flush cadence (see module docstring).
CSV_FLUSH_ROWS = 10     # append to the CSV once this many rows have accumulated
JSON_BATCH_SIZE = 100   # write a new JSON file once this many reports accumulate

FIELDNAMES = [
    "Filename",
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


# --- small value helpers --------------------------------------------------

def enum_or_value(val: Any) -> Any:
    return val.name if isinstance(val, enum.Enum) else val


def finding_to_dict(finding: Any) -> dict[str, Any]:
    if is_dataclass(finding):
        return asdict(finding)
    if isinstance(finding, dict):
        return finding
    return getattr(finding, "__dict__", {})


def text_from(value: Any) -> str:
    if value in {None, ""}:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return enum_or_value(value)


def present(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (dict, list, tuple, set)) and not value:
        return False
    return True


def finding_description(finding: dict[str, Any]) -> str:
    for key in ("description", "explain", "title", "message", "reason"):
        if finding.get(key):
            return text_from(finding[key])
    return ""


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


def bucket_for_verdict(verdict: Any) -> str:
    return VERDICT_BUCKETS.get(str(verdict).upper(), "suspicious")


# --- row / report builders ------------------------------------------------

def row_for_finding(
    filename: str,
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
    location = text_from(finding.get("location"))
    if location:
        payload["location"] = location
    return {key: value for key, value in payload.items() if present(value)}


def json_report(
    filename: str,
    verdict: str,
    risk_score: float,
    findings: list[dict[str, Any]],
    error: str = "",
) -> dict[str, Any]:
    payload = {
        "file_name": filename,
        "verdict": verdict,
        "risk_score": round(risk_score, 4),
        "findings": [json_finding(finding) for finding in findings],
    }
    if error:
        payload["error"] = error
    return payload


def scan_file(scanner: Any, file_path: Path, base_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Scan one resume -> (json_report_payload, [csv_row, ...])."""
    filename = file_path.relative_to(base_dir).as_posix()
    try:
        report = scanner.scan(str(file_path))
        findings = [finding_to_dict(f) for f in getattr(report, "findings", [])]
        verdict = enum_or_value(getattr(report, "verdict", "UNKNOWN"))
        risk_score = float(getattr(report, "risk_score", 0.0) or 0.0)
        threats = detected_threats(findings)
        payload = json_report(filename, verdict, risk_score, findings)
        if not findings:
            rows = [row_for_finding(filename, verdict, risk_score, 0, "", {})]
        else:
            rows = [
                row_for_finding(filename, verdict, risk_score, len(findings), threats, f)
                for f in findings
            ]
        return payload, rows
    except Exception as exc:  # noqa: BLE001 — surface any parse/scan failure per file
        error = f"{type(exc).__name__}: {exc}"
        payload = json_report(filename, "ERROR", 0.0, [], error)
        return payload, [row_for_finding(filename, "ERROR", 0.0, 0, "", {}, error)]


def iter_files(path: Path, exclude_dir: Path | None = None) -> Iterable[Path]:
    """Yield resume files under `path` (or `path` itself if it is a file)."""
    exclude = exclude_dir.resolve() if exclude_dir else None
    if path.is_file():
        yield path
        return
    for child in sorted(path.rglob("*")):
        if not (child.is_file() and child.suffix.lower() in RESUME_EXTENSIONS):
            continue
        if exclude and exclude in child.resolve().parents:
            continue  # don't rescan files we already sorted into the output tree
        yield child


def sort_file(file_path: Path, base_dir: Path, run_dir: Path, verdict: Any) -> str:
    """Copy file into run_dir/<bucket>/<relative path>; return the bucket."""
    bucket = bucket_for_verdict(verdict)
    dest = run_dir / bucket / file_path.relative_to(base_dir)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, dest)
    return bucket


# --- incremental result writer -------------------------------------------

class ResultWriter:
    """Streams results to disk: CSV rows APPENDED every CSV_FLUSH_ROWS, JSON
    reports written in fresh files of JSON_BATCH_SIZE each. Keeps memory flat
    and leaves partial results on disk if the run is interrupted."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.csv_path = run_dir / "resume_scan_report.csv"
        self._row_buf: list[dict[str, Any]] = []
        self._json_buf: list[dict[str, Any]] = []
        self._csv_header_written = False
        self._json_file_idx = 0
        self.total_rows = 0
        self.total_reports = 0
        self.json_files = 0

    def add(self, json_payload: dict[str, Any], csv_rows: list[dict[str, Any]]) -> None:
        self._json_buf.append(json_payload)
        self._row_buf.extend(csv_rows)
        if len(self._row_buf) >= CSV_FLUSH_ROWS:
            self._flush_csv()
        if len(self._json_buf) >= JSON_BATCH_SIZE:
            self._flush_json()

    def _flush_csv(self) -> None:
        if not self._row_buf:
            return
        mode = "a" if self._csv_header_written else "w"
        with self.csv_path.open(mode, newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            if not self._csv_header_written:
                writer.writeheader()
                self._csv_header_written = True
            writer.writerows(self._row_buf)
        self.total_rows += len(self._row_buf)
        self._row_buf.clear()

    def _flush_json(self) -> None:
        if not self._json_buf:
            return
        self._json_file_idx += 1
        path = self.run_dir / f"resume_scan_report_{self._json_file_idx:03d}.json"
        path.write_text(
            json.dumps(self._json_buf, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        self.total_reports += len(self._json_buf)
        self.json_files += 1
        self._json_buf.clear()

    def close(self) -> None:
        self._flush_csv()
        self._flush_json()


# --- parallel scanning (opt-in via --workers) -----------------------------
# Processes, not threads: scanning is CPU-bound and the Docling PDF worker is
# serialized by a lock, so only separate processes give real parallelism. Each
# worker builds its OWN Scanner ONCE (models load once per process, reused
# across files). Memory scales with --workers — size accordingly.
_WORKER_SCANNER: Any = None
_WORKER_BASE: "Path | None" = None


def _init_worker(config_path_str: str, base_str: str) -> None:
    global _WORKER_SCANNER, _WORKER_BASE
    from doc_firewall import ScanConfig, Scanner
    cfg_path = Path(config_path_str)
    config = ScanConfig.from_yaml(str(cfg_path)) if cfg_path.exists() else ScanConfig()
    _WORKER_SCANNER = Scanner(config=config)
    _WORKER_BASE = Path(base_str)


def _scan_task(file_path_str: str) -> "tuple[str, tuple[dict[str, Any], list[dict[str, Any]]]]":
    return file_path_str, scan_file(_WORKER_SCANNER, Path(file_path_str), _WORKER_BASE)


def load_config(config_path: Path) -> Any:
    from doc_firewall import ScanConfig
    if config_path.exists():
        print(f"Loaded configuration from {config_path}")
        return ScanConfig.from_yaml(str(config_path))
    print(f"Config file not found: {config_path}. Using defaults.")
    return ScanConfig()


def _fmt_hms(seconds: float) -> str:
    total = int(round(seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("path", type=Path, help="Resume file or folder of resumes")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                        help=f"YAML scan config (default: {DEFAULT_CONFIG.name})")
    parser.add_argument("--out", type=Path, default=Path("reports/resume_scan"),
                        help="Parent dir; a timestamped output_<ts>/ run folder is created under it "
                             "(default: reports/resume_scan)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Parallel worker processes for folders (default: 1 = sequential). "
                             "Each worker loads its own models, so memory scales with this number; "
                             "only worth raising for large corpora.")
    args = parser.parse_args()

    if not args.path.exists():
        raise SystemExit(f"Path does not exist: {args.path}")

    try:
        from doc_firewall import Scanner
    except ImportError as exc:
        raise SystemExit("doc-firewall is not installed. Run `pip install -e \".[ml]\"`.") from exc

    base = args.path if args.path.is_dir() else args.path.parent

    # One timestamped folder per run holds the buckets + CSV + JSON batches.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = args.out / f"output_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    files = list(iter_files(args.path, exclude_dir=run_dir))
    if not files:
        raise SystemExit(
            f"No resume files ({', '.join(sorted(RESUME_EXTENSIONS))}) found under {args.path}"
        )

    writer = ResultWriter(run_dir)
    verdict_counts: dict[str, int] = {}
    bucket_counts: dict[str, int] = {}
    start = time.perf_counter()

    def handle(file_path: Path, json_payload: dict[str, Any], csv_rows: list[dict[str, Any]], idx: int) -> None:
        writer.add(json_payload, csv_rows)
        verdict = str(json_payload.get("verdict", "UNKNOWN"))
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        bucket = sort_file(file_path, base, run_dir, verdict)
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        threats = json_payload.get("findings") and detected_threats(
            [{"threat_id": f.get("threat_id")} for f in json_payload["findings"]]
        ) or ""
        risk = json_payload.get("risk_score", 0.0)
        suffix = f"  [{threats}]" if threats else ""
        print(f"[{idx}/{len(files)}] {json_payload['file_name']} -> {verdict} (risk {risk}){suffix}")

    print(f"Scanning {len(files)} resume(s) -> {run_dir}\n")

    workers = max(1, args.workers)
    if workers > 1 and len(files) > 1:
        workers = min(workers, len(files))
        print(f"Using {workers} worker processes…")
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_init_worker,
            initargs=(str(args.config), str(base)),
        ) as pool:
            # pool.map preserves input order, so the CSV/JSON match a sequential run.
            for idx, (file_path_str, (json_payload, csv_rows)) in enumerate(
                pool.map(_scan_task, [str(f) for f in files]), start=1
            ):
                handle(Path(file_path_str), json_payload, csv_rows, idx)
    else:
        config = load_config(args.config)
        scanner = Scanner(config=config)
        for idx, file_path in enumerate(files, start=1):
            json_payload, csv_rows = scan_file(scanner, file_path, base)
            handle(file_path, json_payload, csv_rows, idx)

    writer.close()  # flush any remaining rows / final JSON batch
    elapsed = time.perf_counter() - start

    # --- end-of-run summary ---
    print("\n" + "=" * 60)
    print(f"Scanned {len(files)} resume(s) in {_fmt_hms(elapsed)}")
    print("Verdicts: " + ", ".join(f"{n} {v}" for v, n in sorted(verdict_counts.items())))
    print("Buckets : " + ", ".join(f"{n} {b}" for b, n in sorted(bucket_counts.items())))
    print(f"Output  : {run_dir}")
    print(f"          {writer.csv_path.name} ({writer.total_rows} rows), "
          f"{writer.json_files} JSON file(s) ({writer.total_reports} reports)")
    print("=" * 60)

    # Non-zero exit if anything errored or was blocked — handy for CI gating.
    return 1 if verdict_counts.get("ERROR") or verdict_counts.get("BLOCK") else 0


if __name__ == "__main__":
    raise SystemExit(main())
