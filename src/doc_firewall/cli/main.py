from __future__ import annotations
import json
import argparse
import sys
import os
from datetime import datetime
from ..scanner import scan, Scanner
from ..config import ScanConfig
from ..policy import PolicyEngine


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
                "details": f.explain or "",
                "malicious_text": f.evidence.get("malicious_text", "")
            } for f in report.findings
        ]
    }


def _cmd_scan(args) -> None:
    config = ScanConfig(profile=args.profile)
    if args.enable_ml:
        config.enable_advanced_ahocorasick = True
        config.enable_advanced_bert = True
        config.enable_advanced_tfidf = True
        config.enable_credential_entropy = True
    if getattr(args, "audit_log", None):
        config.audit_log_path = args.audit_log

    policy_engine = None
    if getattr(args, "policy_file", None):
        try:
            policy_engine = PolicyEngine(args.policy_file)
        except Exception as e:
            print(f"Error loading policy file '{args.policy_file}': {e}", file=sys.stderr)
            sys.exit(1)

    policy_name = getattr(args, "policy_name", None)
    scanner = Scanner(config=config, policy_engine=policy_engine)
    paths_to_scan = []

    _EXTENSIONS = ('.pdf', '.docx', '.pptx', '.xlsx', '.rtf', '.html', '.htm')
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.lower().endswith(_EXTENSIONS):
                    paths_to_scan.append(os.path.join(root, f))
    elif os.path.isfile(args.path):
        paths_to_scan.append(args.path)
    else:
        print(f"Error: Path {args.path} not found.", file=sys.stderr)
        sys.exit(1)

    all_reports = []
    siem_events = []

    for p in paths_to_scan:
        try:
            report = scanner.scan(p, policy_name=policy_name)
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
        print(f"Wrote reports to {args.output}", file=sys.stderr)
        _apply_exit_code(getattr(args, "fail_on", "none"), all_reports)
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

    _apply_exit_code(getattr(args, "fail_on", "none"), all_reports)


# Verdict severity ordering for --fail-on gating.
_VERDICT_RANK = {"ALLOW": 0, "FLAG": 1, "BLOCK": 2}
# Distinct from usage/operational errors (exit 1) so CI can tell a policy
# failure ("a scanned document was flagged/blocked") apart from a crash.
_FAIL_EXIT_CODE = 2


def _apply_exit_code(fail_on: str, all_reports) -> None:
    """Exit non-zero when a scanned document's verdict meets the --fail-on
    threshold, so the CLI can gate CI / shell ingestion pipelines. Default
    ('none') preserves the historical always-0 behaviour for existing scripts.
    """
    if fail_on == "none":
        return
    threshold = _VERDICT_RANK["BLOCK"] if fail_on == "block" else _VERDICT_RANK["FLAG"]
    worst = max(
        (_VERDICT_RANK.get(r.verdict.value, 0) for _, r in all_reports),
        default=0,
    )
    if worst >= threshold:
        sys.exit(_FAIL_EXIT_CODE)


def _cmd_rules_test(args) -> None:
    """Validate and dry-run a YARA rules file against an optional test directory."""
    rules_path = args.rules_file
    if not os.path.isfile(rules_path):
        print(f"Error: rules file '{rules_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        import yara  # type: ignore
    except ImportError:
        print("Error: yara-python is not installed. Run: pip install yara-python", file=sys.stderr)
        sys.exit(1)

    # Compile
    try:
        compiled = yara.compile(filepath=rules_path)
    except yara.SyntaxError as exc:
        print(f"YARA syntax error:\n  {exc}", file=sys.stderr)
        sys.exit(1)

    rules_meta = list(compiled)
    print(f"OK — compiled {len(rules_meta)} rule(s) from '{rules_path}'")
    for rule in rules_meta:
        ns = rule.namespace if hasattr(rule, "namespace") else ""
        print(f"  [{ns or 'default'}] {rule.rule}")

    if not args.test_dir:
        sys.exit(0)

    # Test against sample documents
    test_dir = args.test_dir
    if not os.path.isdir(test_dir):
        print(f"Error: test directory '{test_dir}' not found.", file=sys.stderr)
        sys.exit(1)

    _EXTENSIONS = ('.pdf', '.docx', '.pptx', '.xlsx', '.rtf', '.html', '.htm', '.yar', '.txt')
    hits = 0
    total = 0
    for root, _, files in os.walk(test_dir):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            try:
                matches = compiled.match(filepath=fpath)
                total += 1
                if matches:
                    hits += 1
                    rule_names = ", ".join(m.rule for m in matches)
                    print(f"  MATCH  {fpath!r}  →  [{rule_names}]")
                else:
                    print(f"  clean  {fpath!r}")
            except Exception as exc:
                print(f"  ERROR  {fpath!r}  —  {exc}")

    print(f"\nResult: {hits}/{total} files matched at least one rule.")
    sys.exit(0)


def _cmd_audit_verify(args) -> None:
    from ..audit_log import verify_chain
    result = verify_chain(
        args.log_file,
        expected_count=getattr(args, "expected_count", None),
    )
    print(str(result))
    sys.exit(0 if result.valid else 1)


def _cmd_audit_keygen(args) -> None:
    """Generate a new API key and print its salted PBKDF2 hash suitable for
    the key store JSON."""
    import secrets
    import hashlib
    raw_key = secrets.token_urlsafe(32)
    iterations = 600_000  # OWASP-recommended floor for PBKDF2-HMAC-SHA256 (2023)
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt, iterations)
    key_hash = f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"
    print(f"Raw key  (share with client, never store): {raw_key}")
    print(f"Hash     (store in api_keys.json):         {key_hash}")
    entry = {"id": args.name or "new-key", "name": args.name or "", "hash": key_hash}
    print(f"\nJSON entry to add to api_keys.json:\n{json.dumps(entry, indent=2)}")


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="doc-firewall",
        description="LLM-aware secure document intake scanner.",
    )
    sub = ap.add_subparsers(dest="command")

    # ── scan (default, also triggered when no subcommand is given) ──────────
    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", help="File or directory to scan")
    scan_p.add_argument(
        "--profile", default="balanced",
        choices=["lenient", "balanced", "strict"],
        help="Scanning thresholds profile",
    )
    scan_p.add_argument(
        "--enable-ml", action="store_true",
        help="Enable deep learning NLP and advanced heuristic detectors",
    )
    scan_p.add_argument("--output", help="Write findings to a file")
    scan_p.add_argument(
        "--siem-format", action="store_true",
        help="Format JSON output for SIEM/DataDog/Splunk ingest",
    )
    scan_p.add_argument("--json", action="store_true", help="Print JSON report")
    scan_p.add_argument(
        "--fail-on", choices=["none", "flag", "block"], default="none",
        dest="fail_on",
        help=(
            "Exit non-zero (code 2) when a scanned document's verdict meets or "
            "exceeds this level, for CI / pipeline gating. Default: none "
            "(always exit 0)."
        ),
    )
    scan_p.add_argument(
        "--audit-log", metavar="PATH",
        help="Append scan results to a tamper-evident audit log at PATH",
    )
    scan_p.add_argument(
        "--policy-file", metavar="PATH",
        help="Path to a YAML policy file (allow/deny lists, custom weights, profiles)",
    )
    scan_p.add_argument(
        "--policy-name", metavar="NAME",
        help="Named policy within the policy file to apply (overrides file-glob matching)",
    )

    # ── audit subcommand ────────────────────────────────────────────────────
    audit_p = sub.add_parser("audit", help="Audit log utilities")
    audit_sub = audit_p.add_subparsers(dest="audit_command")

    verify_p = audit_sub.add_parser(
        "verify-chain",
        help="Verify the integrity chain of an audit log file",
    )
    verify_p.add_argument("log_file", help="Path to the audit JSONL log file")
    verify_p.add_argument(
        "--expected-count", type=int, metavar="N", dest="expected_count",
        help=(
            "Expected number of entries (from an external anchor). When given, "
            "a shorter log is flagged as truncated. Set "
            "DOC_FIREWALL_AUDIT_HMAC_KEY to verify a keyed (HMAC) chain."
        ),
    )

    keygen_p = audit_sub.add_parser(
        "keygen",
        help="Generate a new API key and its hash for the key store",
    )
    keygen_p.add_argument(
        "--name", default="new-key",
        help="Human-readable name / id for this key",
    )

    # ── rules subcommand ───────────────────────────────────────────────────
    rules_p = sub.add_parser("rules", help="YARA rule utilities")
    rules_sub = rules_p.add_subparsers(dest="rules_command")

    test_p = rules_sub.add_parser(
        "test",
        help="Validate a YARA rules file and optionally test against sample documents",
    )
    test_p.add_argument("rules_file", help="Path to the .yar rules file to validate")
    test_p.add_argument(
        "--test-dir", metavar="DIR",
        help="Directory of sample files to match against (optional)",
    )

    # ── Backward-compatible: treat first positional as a scan path ──────────
    # If the first argument is not a known subcommand and looks like a path,
    # inject "scan" so the old invocation style still works.
    raw_args = sys.argv[1:]
    if raw_args and raw_args[0] not in ("scan", "audit", "rules", "-h", "--help"):
        raw_args = ["scan"] + raw_args

    args = ap.parse_args(raw_args)

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "audit":
        if args.audit_command == "verify-chain":
            _cmd_audit_verify(args)
        elif args.audit_command == "keygen":
            _cmd_audit_keygen(args)
        else:
            audit_p.print_help()
            sys.exit(1)
    elif args.command == "rules":
        if args.rules_command == "test":
            _cmd_rules_test(args)
        else:
            rules_p.print_help()
            sys.exit(1)
    else:
        ap.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
