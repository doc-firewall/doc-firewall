"""W8 (0.5.0) — robustness of the raw-bytes parsers and sanitizers.

The scanner parses hostile input. 0.4.8–0.5.0 added several raw-bytes
parsers and a decryption path; this property-based suite feeds them random
and adversarially-structured bytes and asserts they NEVER raise, return the
declared type, and complete within a time bound (no hang / unbounded
allocation). hypothesis-driven; skips cleanly if hypothesis is absent.
"""
from __future__ import annotations

import os
import sys
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
    _HAS_HYP = True
except ImportError:  # pragma: no cover
    _HAS_HYP = False
    pytest.skip("hypothesis not installed", allow_module_level=True)

from doc_firewall.analyzers.pdf.action_resolver import resolve_pdf_actions, summarize_actions
from doc_firewall.analyzers.pdf.font_divergence import analyze_font_divergence
from doc_firewall.analyzers.pdf.hidden_text_extract import extract_hidden_pdf_text
from doc_firewall.analyzers.pdf.uri_classify import classify_pdf_uris
from doc_firewall.sanitize import sanitize_file
from doc_firewall.utils.pdf_decrypt import is_pdf_encrypted, try_decrypt_pdf

# Bytes strategies: pure-random plus PDF-token-flavoured fragments so the
# parsers actually exercise their branches, not just bail at byte 0.
_TOKENS = [
    b"%PDF-1.5", b"obj", b"endobj", b"stream", b"endstream", b"/ObjStm",
    b"/OpenAction", b"/AA", b"/JavaScript", b"/JS", b"/Launch", b"/Next",
    b"/URI", b"<<", b">>", b"[", b"]", b"(", b")", b" R", b"/N ", b"/First ",
    b"/FlateDecode", b"file://", b"javascript:", b"\\", b"0 0", b"trailer",
    b"/ToUnicode", b"/Encoding", b"/Differences", b"/A", b"beginbfchar",
    b"endbfchar", b"beginbfrange", b"endbfrange", b"<0041>",
]
_fragments = st.lists(
    st.one_of(st.sampled_from(_TOKENS), st.binary(max_size=24)),
    max_size=40,
).map(b"".join)
_blobs = st.one_of(st.binary(max_size=4000), _fragments)

_SLOW_MS = 2000  # generous deadline — a hang/OOM would blow far past this


@settings(max_examples=400, deadline=_SLOW_MS)
@given(_blobs)
def test_resolve_pdf_actions_never_raises(blob):
    out = resolve_pdf_actions(blob)
    assert isinstance(out, list)
    # summarize must also survive whatever shape resolve produced.
    ev = summarize_actions(out)
    assert isinstance(ev, dict)


@settings(max_examples=400, deadline=_SLOW_MS)
@given(_blobs)
def test_extract_hidden_pdf_text_never_raises(blob):
    out = extract_hidden_pdf_text(blob)
    assert isinstance(out, list)
    assert all(isinstance(s, str) for s in out)


@settings(max_examples=400, deadline=_SLOW_MS)
@given(_blobs)
def test_classify_pdf_uris_never_raises(blob):
    suspicious, artifacts = classify_pdf_uris(blob)
    assert isinstance(suspicious, list) and isinstance(artifacts, list)


@settings(max_examples=400, deadline=_SLOW_MS)
@given(_blobs)
def test_font_divergence_never_raises(blob):
    out = analyze_font_divergence(blob)
    assert isinstance(out, list)
    assert all(isinstance(d, dict) for d in out)


def _write_tmp(data: bytes, suffix: str) -> str:
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return p


@settings(max_examples=150, deadline=_SLOW_MS)
@given(st.binary(max_size=2000))
def test_decrypt_and_encrypt_check_never_raise(data):
    p = _write_tmp(data, ".pdf")
    try:
        assert isinstance(is_pdf_encrypted(p), bool)
        out, reason = try_decrypt_pdf(p, ["", "pw"])
        assert out is None or isinstance(out, str)
        if out:
            os.remove(out)
    finally:
        os.remove(p)


@settings(max_examples=120, deadline=_SLOW_MS)
@given(st.binary(max_size=1500))
def test_sanitize_csv_html_never_raise(data):
    for ext in (".csv", ".html"):
        p = _write_tmp(data, ext)
        try:
            res = sanitize_file(p, ext.lstrip("."))
            assert res.sanitized in (True, False)
            if res.output_path and os.path.exists(res.output_path):
                os.remove(res.output_path)
        finally:
            os.remove(p)


@settings(max_examples=120, deadline=_SLOW_MS)
@given(st.lists(st.tuples(st.text(max_size=12), st.binary(max_size=200)), max_size=8))
def test_sanitize_ooxml_on_malformed_zip_never_raises(members):
    # Build an arbitrary (possibly nonsense) zip and feed it to the OOXML
    # sanitizer — it must degrade gracefully, never raise.
    fd, p = tempfile.mkstemp(suffix=".docx")
    os.close(fd)
    try:
        try:
            with zipfile.ZipFile(p, "w") as zf:
                for name, data in members:
                    safe = (name or "f").replace("/", "_") or "f"
                    zf.writestr(safe, data)
        except Exception:
            return  # zip construction itself failed — not under test
        res = sanitize_file(p, "docx")
        assert res.sanitized in (True, False)
        if res.output_path and os.path.exists(res.output_path):
            assert zipfile.is_zipfile(res.output_path)
            os.remove(res.output_path)
    finally:
        os.remove(p)


# ── Adversarially-structured inputs (not random) ─────────────────────────

class TestAdversarialStructures:
    def test_deeply_nested_dicts_bounded(self):
        # Pathological nesting must not blow the stack or hang.
        blob = b"%PDF-1.5\n1 0 obj /OpenAction " + b"<<" * 5000 + b">>" * 5000 + b" endobj"
        assert isinstance(resolve_pdf_actions(blob), list)

    def test_objstm_lying_about_counts(self):
        # /ObjStm claiming a huge N / First it doesn't have.
        blob = (
            b"%PDF-1.5\n5 0 obj << /Type /ObjStm /N 9999999 /First 999999 "
            b"/Length 4 >> stream\nXXXX\nendstream endobj"
        )
        assert isinstance(resolve_pdf_actions(blob), list)
        assert isinstance(extract_hidden_pdf_text(blob), list)

    def test_unterminated_constructs(self):
        for blob in (
            b"%PDF /OpenAction << /S /JavaScript /JS (" + b"A" * 100000,
            b"/URI (" + b"\\" * 50000,
            b"/ObjStm stream\n" + b"\xff" * 50000,
        ):
            assert isinstance(resolve_pdf_actions(blob), list)
            assert isinstance(extract_hidden_pdf_text(blob), list)
