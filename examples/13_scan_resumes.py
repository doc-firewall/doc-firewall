#!/usr/bin/env python3
"""
Example 13: Scan a folder (or single file) of resumes.

A resume-focused companion to 12_scan_folder.py. Everything is configurable
through a YAML file (see resume.yaml) just like 04_yaml_config_scan.py, so the
detection policy lives next to the data rather than hard-coded here.

Usage:
    python 13_scan_resumes.py <path>                       # uses resume.yaml
    python 13_scan_resumes.py <path> --config my.yaml
    python 13_scan_resumes.py <path> --json out/report.json
    python 13_scan_resumes.py resume.pdf                   # single file works too

<path> may be a single resume or a folder; folders are scanned recursively.
"""

from __future__ import annotations

import argparse
import enum
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

# Allow running straight from a checkout: import doc_firewall from ../src.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Resume corpora are overwhelmingly these formats.
RESUME_EXTENSIONS = {".pdf", ".docx", ".docm", ".doc", ".odt", ".rtf"}

# Default config lives beside this script.
DEFAULT_CONFIG = Path(__file__).resolve().parent / "resume.yaml"


def enum_or_value(val: Any) -> Any:
    return val.name if isinstance(val, enum.Enum) else val


def iter_files(path: Path) -> Iterable[Path]:
    """Yield resume files under `path` (or `path` itself if it is a file)."""
    if path.is_file():
        yield path
        return
    for child in sorted(path.rglob("*")):
        if child.is_file() and child.suffix.lower() in RESUME_EXTENSIONS:
            yield child


def load_config(config_path: Path) -> Any:
    from doc_firewall import ScanConfig

    if config_path.exists():
        print(f"Loaded configuration from {config_path}")
        return ScanConfig.from_yaml(str(config_path))
    print(f"Config file not found: {config_path}. Using defaults.")
    return ScanConfig()


def finding_payload(finding: Any) -> dict[str, Any]:
    evidence = getattr(finding, "evidence", None)
    payload = {
        "threat_id": str(enum_or_value(getattr(finding, "threat_id", ""))),
        "title": getattr(finding, "title", ""),
        "severity": enum_or_value(getattr(finding, "severity", "")),
        "confidence": getattr(finding, "confidence", None),
        "explain": getattr(finding, "explain", "") or "",
        "mitre_technique": getattr(finding, "mitre_technique", None),
        "attack_objective": getattr(finding, "attack_objective", None),
    }
    if isinstance(evidence, dict) and evidence:
        payload["evidence"] = evidence
    return {k: v for k, v in payload.items() if v not in (None, "")}


def scan_one(scanner: Any, file_path: Path, base: Path) -> dict[str, Any]:
    name = file_path.relative_to(base).as_posix() if base in file_path.parents or base == file_path.parent else file_path.name
    try:
        report = scanner.scan(str(file_path))
        return {
            "file": name,
            "verdict": enum_or_value(getattr(report, "verdict", "UNKNOWN")),
            "risk_score": round(float(getattr(report, "risk_score", 0.0) or 0.0), 4),
            "findings": [finding_payload(f) for f in getattr(report, "findings", []) or []],
        }
    except Exception as exc:  # noqa: BLE001 — surface any parse/scan failure per file
        return {"file": name, "verdict": "ERROR", "risk_score": 0.0,
                "findings": [], "error": f"{type(exc).__name__}: {exc}"}


def print_result(result: dict[str, Any]) -> None:
    verdict = result["verdict"]
    print(f"\n{result['file']}  ->  {verdict}  (risk {result['risk_score']})")
    if result.get("error"):
        print(f"    ! {result['error']}")
        return
    if not result["findings"]:
        print("    no threats detected")
        return
    for f in result["findings"]:
        line = f"    - [{f.get('severity', '?')}] {f['threat_id']} {f.get('title', '')}".rstrip()
        conf = f.get("confidence")
        if conf is not None:
            line += f" (conf {conf})"
        print(line)
        if f.get("explain"):
            print(f"        {f['explain']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path, help="Resume file or folder of resumes")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                        help=f"YAML scan config (default: {DEFAULT_CONFIG.name})")
    parser.add_argument("--json", type=Path, default=None,
                        help="Optional path to write a JSON report of all results")
    args = parser.parse_args()

    if not args.path.exists():
        raise SystemExit(f"Path does not exist: {args.path}")

    try:
        from doc_firewall import Scanner
    except ImportError as exc:
        raise SystemExit("doc-firewall is not installed. Run `pip install -e \".[ml]\"`.") from exc

    config = load_config(args.config)
    scanner = Scanner(config=config)

    base = args.path if args.path.is_dir() else args.path.parent
    results: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for file_path in iter_files(args.path):
        result = scan_one(scanner, file_path, base)
        results.append(result)
        print_result(result)
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1

    if not results:
        raise SystemExit(f"No resume files ({', '.join(sorted(RESUME_EXTENSIONS))}) found under {args.path}")

    summary = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
    print(f"\nScanned {len(results)} resume(s): {summary}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, ensure_ascii=False, default=str),
                             encoding="utf-8")
        print(f"Wrote JSON report to {args.json}")

    # Non-zero exit if anything errored or was blocked — handy for CI gating.
    return 1 if counts.get("ERROR") or counts.get("BLOCK") else 0


if __name__ == "__main__":
    raise SystemExit(main())
