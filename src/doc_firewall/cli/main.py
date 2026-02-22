from __future__ import annotations
import json
import argparse
from ..scanner import scan
from ..config import ScanConfig


def main():
    ap = argparse.ArgumentParser(
        prog="doc-guard", description="Secure document intake scanner (PDF/DOCX)."
    )
    ap.add_argument("path", help="File to scan")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()
    report = scan(args.path, config=ScanConfig())
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Verdict: {report.verdict.value}  Risk: {report.risk_score:.3f}")
        for f in report.findings:
            print(f"- [{f.severity.value}] {f.threat_id.value}: {f.title}")
            if f.explain:
                print(f"  {f.explain}")
