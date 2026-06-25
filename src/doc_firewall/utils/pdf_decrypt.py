"""W6 (0.5.0) — transparent PDF decryption for scanning.

Answers the question "if a PDF is encrypted, does a decryption library help?"

It depends on the encryption type:

  * **Empty-user-password / permissions-only encryption** — extremely common
    ("you can open this but not print/edit"). The content IS encrypted, but
    the *user* password is the empty string; the owner password only gates
    permissions. A library (pikepdf, wrapping QPDF) decrypts these with **no
    password at all**, so the scanner can read and scan the full content
    instead of flagging it as an un-inspectable blind spot. This is the big
    win — a large fraction of "encrypted" PDFs fall here.
  * **Real user-password encryption** — the content key is derived from a
    password the scanner doesn't have. A library only helps if the caller
    supplies the password (``ScanConfig.pdf_passwords``); otherwise the
    content genuinely cannot be read and the unscannable policy applies.

Decryption is to a temporary file that the caller scans and then deletes —
the decrypted plaintext is never written back next to the original.

pikepdf is an OPTIONAL dependency (lazy-imported); when absent this returns
None and the scanner falls back to the existing unscannable handling, so the
base install is unaffected.
"""
from __future__ import annotations

import os
import tempfile
from typing import List, Optional, Tuple

from ..logger import get_logger

logger = get_logger()

# Passwords always tried first, before any caller-supplied ones. The empty
# string handles the common permissions-only encryption case transparently.
_DEFAULT_PASSWORDS = ("",)


def _pikepdf():
    try:
        import pikepdf  # type: ignore
        return pikepdf
    except Exception:
        return None


def is_pdf_encrypted(path: str) -> bool:
    """Cheap raw-bytes check for an /Encrypt trailer reference."""
    try:
        with open(path, "rb") as f:
            # /Encrypt lives in the trailer; scan a bounded prefix+suffix.
            head = f.read(4096)
            f.seek(max(0, os.path.getsize(path) - 8192))
            tail = f.read(8192)
        return b"/Encrypt" in head or b"/Encrypt" in tail
    except OSError:
        return False


def try_decrypt_pdf(
    path: str, passwords: Optional[List[str]] = None
) -> Tuple[Optional[str], Optional[str]]:
    """Attempt to produce a decrypted copy of an encrypted PDF.

    Returns ``(decrypted_temp_path, method)`` on success — the caller owns
    the temp file and must delete it — or ``(None, reason)`` on failure,
    where ``reason`` explains why (library missing / wrong password / error).
    Never raises.
    """
    pike = _pikepdf()
    if pike is None:
        return None, "pikepdf not installed (pip install doc-firewall[crypto])"

    candidates: List[str] = list(_DEFAULT_PASSWORDS)
    for p in (passwords or []):
        if p not in candidates:
            candidates.append(p)

    last_err = "no password matched"
    for pw in candidates:
        try:
            with pike.open(path, password=pw) as pdf:
                fd, tmp = tempfile.mkstemp(suffix=".pdf", prefix="docfw_dec_")
                os.close(fd)
                # Save WITHOUT encryption so downstream parsing sees plaintext.
                pdf.save(tmp)
                method = "empty-password" if pw == "" else "supplied-password"
                logger.debug("Decrypted PDF via %s", method)
                return tmp, method
        except pike.PasswordError:
            last_err = "wrong password (a user password is required)"
            continue
        except Exception as e:  # malformed / unsupported encryption
            last_err = f"decryption error: {type(e).__name__}"
            continue
    return None, last_err
