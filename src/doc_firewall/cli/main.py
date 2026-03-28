from __future__ import annotations
import json
import argparse
import sys
import os
from datetime import datetime
from ..scanner import scan, Scanner
from ..config import ScanConfig

def generate_siem_event(report, filepath: str) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": "DocFirewallScan",
        "file": filepath,
        "verdict": report.verdict.value,
        "risk_score": report.risk_score,
        "findings": [
            {
                "threat": f.threat_id.value,
                "severity": f.severity.value,
                "description": f.title,
                "details": f.explain or ""
            } for f in report.findings
        ]
    }

def main():
    ap = argparse.ArgumentParser(
        prog="doc-firewall", description="LLM-aware secure document intake scanner."
    )
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("--profile", default="balanced", choices=["lenient", "balanced", "strict"], help="Scanning thresholds profile")
    ap.add_argument("--enable-ml", action="store_true", help="Enable deep learning NLP and advanced heuristic detectors")
    ap.add_argument("--output", help="Write findings to a specified output file")
    ap.add_argument("--siem-format", action="store_true", help="Format JSON output for SIEM/DataDog/Splunk ingest")
    ap.add_argument("--json", action="store_true", help="Print standard JSON report to stdout")
    args = ap.parse_args()

    config = ScanConfig(profile=args.profile)
    if args.enable_ml:
        config.enable_advanced_ahocorasick = True
        config.enable_advanced_bert = True
        config.enable_advanced_tfidf = True
        config.enable_credential_entropy = True

    scanner = Scanner(config=config)
    paths_to_scan = []

    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.lower().endswith(('.pdf', '.docx', '.pptx', '.xlsx')):
                    paths_to_scan.append(os.path.join(root, f))
    elif os.path.isfile(args.path):
        paths_to_scan.append(args.path)
    else:
        print(f"Error: Path {args.path} not found.")
        sys.exit(1)

    all_reports = []
    siem_events = []

    for p in paths_to_scan:
        try:
            report = scanner.scan_sync(p)
            all_reports.append((p, report))
            siem_events.append(generate_siem_event(report, p))
        except Exception as e:
            print(f"Failed to scan {p}: {e}", file=sys.stderr)

    if args.output:
        with open(args.output, 'w') as f:
            if args.siem_format:
                for event in siem_events:
                    f.write(json.dumps(event) + "\n")
            else:
                json.dump([r.to_dict() for _, r in all_reports], f, indent=2)
        print(f"Wrote reports to {args.output}")
        return

    for p, report in all_reports:
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        elif args.siem_format:
            print(json.dumps(generate_siem_event(report, p)))
        else:
            print(f"--- \nFile: {p}\nVerdict: {report.verdict.value}  Risk: {report.risk_score:.3f}")
            for f in report.findings:
                print(f"- [{f.severity.value}] {f.threat_id.value}: {f.title}")
                if f.explain:
                    print(f"  {f.explain}")

if __name__ == "__main__":
    main()
