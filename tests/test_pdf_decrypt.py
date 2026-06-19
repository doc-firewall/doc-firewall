"""W6 (0.5.0) — transparent PDF decryption for scanning.

The empty-user-password (permissions-only) case is decrypted with no
password so the content is actually scanned; without pikepdf the feature is
a graceful no-op and the existing unscannable handling applies.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.utils.pdf_decrypt import is_pdf_encrypted, try_decrypt_pdf

_HAS_PIKEPDF = importlib.util.find_spec("pikepdf") is not None

_ENCRYPTED_MARKER_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R /Encrypt 9 0 R /ID [<aa><bb>] >>\n%%EOF\n"
)
_PLAIN_PDF = (
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
)


def _write(data: bytes) -> str:
    fd, p = tempfile.mkstemp(suffix=".pdf")
    os.write(fd, data)
    os.close(fd)
    return p


class TestIsEncrypted:
    def test_detects_encrypt_trailer(self):
        p = _write(_ENCRYPTED_MARKER_PDF)
        try:
            assert is_pdf_encrypted(p)
        finally:
            os.unlink(p)

    def test_plain_pdf_not_encrypted(self):
        p = _write(_PLAIN_PDF)
        try:
            assert not is_pdf_encrypted(p)
        finally:
            os.unlink(p)


class TestGracefulDegradation:
    @pytest.mark.skipif(_HAS_PIKEPDF, reason="pikepdf installed; testing absence path")
    def test_no_pikepdf_returns_reason(self):
        p = _write(_ENCRYPTED_MARKER_PDF)
        try:
            out, reason = try_decrypt_pdf(p, [])
            assert out is None
            assert "pikepdf" in reason
        finally:
            os.unlink(p)

    def test_never_raises_on_garbage(self):
        p = _write(b"not a pdf at all")
        try:
            out, _reason = try_decrypt_pdf(p, ["x"])
            assert out is None  # nothing to decrypt / no lib
        finally:
            os.unlink(p)


@pytest.mark.skipif(not _HAS_PIKEPDF, reason="requires pikepdf")
class TestDecryptionWithPikepdf:
    def _make_encrypted(self, owner="owner", user="") -> str:
        import pikepdf
        plain = pikepdf.new()
        plain.add_blank_page()
        fd, src = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        plain.save(src, encryption=pikepdf.Encryption(owner=owner, user=user))
        return src

    def test_empty_user_password_decrypts(self):
        # Permissions-only encryption (empty user password) → decrypt with
        # NO supplied password.
        src = self._make_encrypted(owner="secret", user="")
        try:
            out, method = try_decrypt_pdf(src, [])
            assert out is not None
            assert method == "empty-password"
            assert os.path.exists(out)
            assert not is_pdf_encrypted(out)  # result is plaintext
            os.unlink(out)
        finally:
            os.unlink(src)

    def test_user_password_requires_supplied(self):
        src = self._make_encrypted(owner="o", user="s3cret")
        try:
            # Without the password → fail with an explanatory reason.
            out, reason = try_decrypt_pdf(src, [])
            assert out is None and "password" in reason.lower()
            # With the password → success.
            out, method = try_decrypt_pdf(src, ["s3cret"])
            assert out is not None and method == "supplied-password"
            os.unlink(out)
        finally:
            os.unlink(src)


class TestConfig:
    def test_flags_present(self):
        cfg = ScanConfig(profile="balanced")
        assert cfg.enable_pdf_decryption is True
        assert cfg.pdf_passwords == []
