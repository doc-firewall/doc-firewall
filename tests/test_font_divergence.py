"""W5 (0.5.0) — measured font/ToUnicode rendered-vs-extracted divergence.

A PDF whose glyph names (what renders) disagree with its ToUnicode map (what
is extracted) is flagged with both strings as evidence; a benign PDF where
they agree is not.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.pdf.font_divergence import (
    _glyph_name_to_unicode,
    analyze_font_divergence,
)
from doc_firewall.config import ScanConfig
from doc_firewall.enums import Verdict
from doc_firewall.scanner import Scanner


def _u16(s: str) -> str:
    return "".join(f"{ord(c):04X}" for c in s)


def _build_pdf(differences_names: list[str], tounicode_chars: list[str]) -> bytes:
    """Build a PDF with one font: /Encoding /Differences (rendered glyphs) and
    a /ToUnicode CMap (extracted text), starting at code 1.

    differences_names: glyph names → rendered text.
    tounicode_chars:   chars → extracted text.
    """
    diff = b"1 " + b" ".join(b"/" + n.encode() for n in differences_names)
    enc = b"5 0 obj\n<< /Type /Encoding /Differences [" + diff + b"] >>\nendobj\n"

    bf = []
    for i, ch in enumerate(tounicode_chars, start=1):
        bf.append(f"<{i:02X}> <{_u16(ch)}>".encode())
    cmap = (
        b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        b"1 begincodespacerange <00> <FF> endcodespacerange\n"
        + str(len(bf)).encode() + b" beginbfchar\n" + b"\n".join(bf)
        + b"\nendbfchar\nendcmap\n"
    )
    tu = (
        b"6 0 obj\n<< /Length " + str(len(cmap)).encode() + b" >>\nstream\n"
        + cmap + b"\nendstream\nendobj\n"
    )
    font = (
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /AAAAAA+Custom "
        b"/Encoding 5 0 R /ToUnicode 6 0 R >>\nendobj\n"
    )
    return (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> >>\nendobj\n"
        + font + enc + tu
        + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


# Rendered "APPROVE" (glyph names) vs extracted "IGNORED" (ToUnicode) — every
# position differs, so the rendered document and the extracted text disagree.
_RENDERED = list("APPROVE")
_EXTRACTED = list("IGNORED")
# Benign: glyph names and ToUnicode both say "APPROVE".
_AGREE_NAMES = list("APPROVE")
_AGREE_CHARS = list("APPROVE")


class TestGlyphNameMapping:
    def test_ascii_letters(self):
        assert _glyph_name_to_unicode("A") == 0x41
        assert _glyph_name_to_unicode("z") == 0x7A
        assert _glyph_name_to_unicode("space") == 0x20
        assert _glyph_name_to_unicode("one") == 0x31

    def test_uni_form(self):
        assert _glyph_name_to_unicode("uni0041") == 0x41

    def test_unknown_returns_none(self):
        assert _glyph_name_to_unicode("g17") is None
        assert _glyph_name_to_unicode("cid1234") is None


class TestAnalysis:
    def test_divergence_detected(self):
        blob = _build_pdf(_RENDERED, _EXTRACTED)
        out = analyze_font_divergence(blob)
        assert out, "divergence not detected"
        rec = out[0]
        assert rec["rendered"] == "APPROVE"
        assert rec["extracted"] == "IGNORED"
        assert rec["diverging_codes"] == 7

    def test_agreement_not_flagged(self):
        blob = _build_pdf(_AGREE_NAMES, _AGREE_CHARS)
        assert analyze_font_divergence(blob) == []

    def test_non_agl_glyph_names_skipped(self):
        # Glyph names with no derivable Unicode (g1, g2…) → no comparison, no FP.
        blob = _build_pdf(["g1", "g2", "g3", "g4", "g5"], list("IGNORE"))
        assert analyze_font_divergence(blob) == []

    def test_garbage_never_raises(self):
        assert analyze_font_divergence(b"\x00\xff" * 3000) == []
        assert analyze_font_divergence(b"/ToUnicode 9 0 R") == []


def _build_pdf_base_encoding(
    rendered: str, extracted: str, *, named_encoding=b"WinAnsi", subset=False
) -> bytes:
    """Build a PDF with a font that has a *named* base encoding (no
    /Differences) and a ToUnicode that maps each printable-ASCII code to a
    different char. The 'rendered' reference is the ASCII identity of each
    code; ``extracted`` is what ToUnicode claims. ``rendered`` chars are used
    as the character codes (so code 'M'==0x4D renders 'M')."""
    assert len(rendered) == len(extracted)
    bf = [f"<{ord(rc):02X}> <{_u16(ec)}>".encode() for rc, ec in zip(rendered, extracted)]
    cmap = (
        b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        b"1 begincodespacerange <00> <FF> endcodespacerange\n"
        + str(len(bf)).encode() + b" beginbfchar\n" + b"\n".join(bf)
        + b"\nendbfchar\nendcmap\n"
    )
    tu = (
        b"6 0 obj\n<< /Length " + str(len(cmap)).encode() + b" >>\nstream\n"
        + cmap + b"\nendstream\nendobj\n"
    )
    tag = b"ABCDEF+" if subset else b""
    font = (
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /" + tag + b"Helvetica "
        b"/Encoding /" + named_encoding + b"Encoding /ToUnicode 6 0 R >>\nendobj\n"
    )
    return (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> >>\nendobj\n"
        + font + tu
        + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


class TestBaseEncodingDivergence:
    """W6 (0.5.0): a lying ToUnicode against a standard-encoded, non-subset
    font needs no /Differences array — the base-encoding path catches it."""

    def test_lying_tounicode_flagged(self):
        # Renders "MAGNETS" (ASCII identity) but extracts "PHISHER". Evidence
        # strings are ordered by character code, so compare as sets.
        out = analyze_font_divergence(_build_pdf_base_encoding("MAGNETS", "PHISHER"))
        assert out, "base-encoding divergence not detected"
        assert set(out[0]["rendered"]) == set("MAGNETS")
        assert set(out[0]["extracted"]) == set("PHISHER")
        assert out[0]["diverging_codes"] == 7
        assert out[0]["rendered"] != out[0]["extracted"]

    def test_truthful_tounicode_not_flagged(self):
        assert analyze_font_divergence(_build_pdf_base_encoding("MAGNETS", "MAGNETS")) == []

    def test_subset_font_skipped(self):
        # Subset fonts remap codes arbitrarily — the ASCII-identity assumption
        # does not hold, so the base-encoding path must NOT fire on them.
        assert analyze_font_divergence(
            _build_pdf_base_encoding("MAGNETS", "PHISHER", subset=True)
        ) == []


def _scan(blob: bytes, **cfg):
    import tempfile
    with tempfile.NamedTemporaryFile("wb", suffix=".pdf", delete=False) as t:
        t.write(blob)
        path = t.name
    try:
        config = ScanConfig(profile="balanced")
        for k, v in cfg.items():
            setattr(config, k, v)
        return Scanner(config).scan(path)
    finally:
        os.unlink(path)


@pytest.mark.adversarial
class TestEndToEnd:
    def test_divergent_pdf_flagged(self):
        r = _scan(_build_pdf(_RENDERED, _EXTRACTED))
        hits = [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "font_text_divergence"
        ]
        assert hits, [f.title for f in r.findings]
        assert hits[0].evidence["rendered_text"] == "APPROVE"
        assert hits[0].evidence["extracted_text"] == "IGNORED"
        assert r.verdict in (Verdict.FLAG, Verdict.BLOCK)

    @pytest.mark.benign
    def test_benign_font_pdf_not_flagged(self):
        r = _scan(_build_pdf(_AGREE_NAMES, _AGREE_CHARS))
        assert not [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "font_text_divergence"
        ]

    def test_disabled(self):
        r = _scan(_build_pdf(_RENDERED, _EXTRACTED), enable_font_divergence=False)
        assert not [
            f for f in r.findings
            if (f.evidence or {}).get("subtype") == "font_text_divergence"
        ]
