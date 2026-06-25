"""Digitally-signed PDFs must not be flagged on their PKCS#7 signature (0.5.0).

Signed PDFs are ubiquitous in real workflows (government, legal, finance). Each
embeds a PKCS#7 / CMS SignedData blob (OID 1.2.840.113549.1.7.2) in the
``/Contents`` of its signature dictionary. The raw-bytes PDF fallback surfaces
that blob as a ``hex_blobs`` artifact, which previously tripped both the T7
embedded-payload heuristic (large hex blob) and the T8 metadata-length check —
flagging essentially every signed PDF as malicious. The signature is now
recognised and excluded, while genuine embedded payloads still fire.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.detectors.embedded_payload import (
    EmbeddedPayloadDetector,
    _is_pkcs7_signature,
)
from doc_firewall.detectors.metadata_injection import MetadataInjectionDetector
from doc_firewall.enums import ThreatID

# A real PDF digital-signature blob prefix (DER SEQUENCE + signedData OID),
# padded out to a realistic length.
_SIG = (
    "308006092a864886f70d010702a0803080020101310b300906052b0e03021a0500"
    "308006092a864886f70d0107010000a0820edb308204a130820389" + "00" * 1200
)
# A non-signature payload of the same shape (an embedded PE executable).
_EXE = "4d5a90000300000004000000ffff0000b8" + "41" * 1200


class TestPkcs7Helper:
    def test_signature_recognised(self):
        assert _is_pkcs7_signature(_SIG)

    def test_executable_not_a_signature(self):
        assert not _is_pkcs7_signature(_EXE)

    def test_random_hex_not_a_signature(self):
        assert not _is_pkcs7_signature("deadbeef" * 100)


class TestEmbeddedPayloadSkipsSignature:
    def _doc(self, blobs):
        return ParsedDocument(
            file_path="x.pdf", file_type="pdf", text="",
            metadata={"hex_blobs": blobs},
        )

    def test_signature_blob_not_flagged(self):
        findings = EmbeddedPayloadDetector().run(self._doc([_SIG]), ScanConfig())
        t7 = [f for f in findings if f.threat_id == ThreatID.T7_EMBEDDED_PAYLOAD]
        assert not t7, "PDF digital signature was flagged as embedded payload"

    def test_real_payload_still_flagged(self):
        findings = EmbeddedPayloadDetector().run(self._doc([_EXE]), ScanConfig())
        t7 = [f for f in findings if f.threat_id == ThreatID.T7_EMBEDDED_PAYLOAD]
        assert t7, "a genuine embedded executable must still be flagged"


class TestMetadataLengthSkipsSignature:
    def test_signature_not_flagged_as_long_metadata(self):
        doc = ParsedDocument(
            file_path="x.pdf", file_type="pdf", text="",
            metadata={"hex_blobs": [_SIG], "title": "Quarterly Report"},
        )
        findings = MetadataInjectionDetector().run(doc, ScanConfig())
        overlong = [
            f for f in findings
            if f.threat_id == ThreatID.T8_METADATA_INJECTION
            and "Length" in (f.title or "")
        ]
        assert not overlong, "signature blob tripped the excessive-length metadata check"

    def test_genuine_long_text_metadata_still_flagged(self):
        doc = ParsedDocument(
            file_path="x.pdf", file_type="pdf", text="",
            metadata={"title": "A " * 4000},  # >5000 chars of real text
        )
        findings = MetadataInjectionDetector().run(doc, ScanConfig())
        overlong = [
            f for f in findings
            if f.threat_id == ThreatID.T8_METADATA_INJECTION
            and "Length" in (f.title or "")
        ]
        assert overlong, "excessive-length text metadata must still be flagged"
