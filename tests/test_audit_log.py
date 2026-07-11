"""Audit-log integrity tests (0.5.1): seq counter, tamper/deletion detection,
tail-truncation via external anchor, and the optional keyed-HMAC chain."""
from __future__ import annotations

import json
import os

from doc_firewall.audit_log import AuditLog, verify_chain
from doc_firewall.enums import Verdict
from doc_firewall.report import ScanReport


def _report(sha: str) -> ScanReport:
    r = ScanReport(file_path="/x", file_type="pdf", sha256=sha, size_bytes=10)
    r.verdict = Verdict.ALLOW
    r.risk_score = 0.0
    return r


def _write(path, n, key=None):
    if key is not None:
        os.environ["DOC_FIREWALL_AUDIT_HMAC_KEY"] = key
    else:
        os.environ.pop("DOC_FIREWALL_AUDIT_HMAC_KEY", None)
    try:
        log = AuditLog(str(path))
        for i in range(n):
            log.write(_report(str(i) * 64))
    finally:
        os.environ.pop("DOC_FIREWALL_AUDIT_HMAC_KEY", None)


def test_valid_chain_has_monotonic_seq(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 3)
    res = verify_chain(str(p))
    assert res.valid and res.entries_checked == 3 and res.last_seq == 2
    seqs = [json.loads(line)["seq"] for line in p.read_text().splitlines()]
    assert seqs == [0, 1, 2]
    assert json.loads(p.read_text().splitlines()[0])["chain_algo"] == "sha256"


def test_in_place_tamper_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 3)
    entries = [json.loads(line) for line in p.read_text().splitlines()]
    entries[1]["verdict"] = "BLOCK"
    p.write_text("\n".join(json.dumps(e, separators=(",", ":")) for e in entries) + "\n")
    assert not verify_chain(str(p)).valid


def test_interior_deletion_detected_by_seq(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 3)
    lines = p.read_text().splitlines()
    p.write_text(lines[0] + "\n" + lines[2] + "\n")  # drop the middle entry
    res = verify_chain(str(p))
    assert not res.valid
    assert any("seq gap" in e for e in res.errors)


def test_tail_truncation_needs_anchor(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 5)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:3]) + "\n")  # remove the last two entries
    # Undetectable from the file alone …
    assert verify_chain(str(p)).valid
    # … but caught with an external count anchor.
    assert not verify_chain(str(p), expected_count=5).valid


def test_resume_continues_seq(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 2)
    _write(p, 1)  # re-open and append one more
    res = verify_chain(str(p))
    assert res.valid and res.last_seq == 2 and res.entries_checked == 3


def test_keyed_hmac_chain_is_unforgeable_without_key(tmp_path):
    p = tmp_path / "keyed.jsonl"
    _write(p, 3, key="super-secret")
    assert json.loads(p.read_text().splitlines()[0])["chain_algo"] == "hmac-sha256"
    # Verifies only when the same key is supplied.
    assert verify_chain(str(p), hmac_key=b"super-secret").valid
    assert not verify_chain(str(p), hmac_key=None).valid  # no key → cannot verify
    assert not verify_chain(str(p), hmac_key=b"wrong-key").valid


def test_version_not_hardcoded_040(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 1)
    entry = json.loads(p.read_text().splitlines()[0])
    assert entry["library_version"] != "0.4.0"
