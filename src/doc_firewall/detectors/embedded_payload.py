from __future__ import annotations

import base64
import math
import os
import re
from typing import List

from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..enums import Severity, ThreatID, VerdictClass
from ..logger import get_logger
from ..report import Finding
from .base import Detector

logger = get_logger()

# DER object identifier for PKCS#7 / CMS SignedData (1.2.840.113549.1.7.2) — the
# structure a PDF digital signature embeds in the /Contents of its signature
# dictionary. Digitally-signed PDFs are ubiquitous in real-world workflows
# (government, legal, finance), so their signature blob must not be mistaken for
# an embedded executable payload. A genuine signature is a DER SEQUENCE (0x30…)
# whose signedData OID appears in the first few dozen bytes.
_PKCS7_SIGNED_DATA_OID = "2a864886f70d010702"


def _is_pkcs7_signature(blob: str) -> bool:
    head = blob[:80].lower()
    return head.startswith("30") and _PKCS7_SIGNED_DATA_OID in head


class EmbeddedPayloadDetector(Detector):
    name = "embedded_payload"

    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculates Shannon entropy for specific string"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        if not config.enable_embedded_content_checks:
            return []

        logger.debug(
            "EmbeddedPayloadDetector running",
            file_path=doc.file_path,
            text_len=len(doc.text or ""),
            metadata_keys=list(doc.metadata.keys()) if doc.metadata else None,
        )
        findings = []
        text = doc.text or ""

        # 1. Base64 Payload Detection (hardened — item 0.7)
        # Matches both standard (+/) and URL-safe (-_) Base64 alphabets.
        # Minimum size lowered from 1366 to 200 chars for deep scan (catches stubs).
        # Entropy threshold lowered from 4.5 to 3.5 (catches PowerShell ~4.1).
        # Secondary "dangerous content" check bypasses entropy for high-risk decoded blobs.
        # Multi-level decode: up to 3 layers (catches double-encoded payloads).
        _DANGEROUS_DECODED = re.compile(
            rb"import|eval|exec|powershell|wget|curl|MZ\x90|"
            rb"\x7fELF|/bin/sh|cmd\.exe",
            re.IGNORECASE,
        )
        _B64_RE = re.compile(r"[A-Za-z0-9+/\-_]{200,}={0,2}")

        b64_reported = False
        for match in _B64_RE.finditer(text):
            if b64_reported:
                break
            blob = match.group(0)
            # Filter out common benign Base64 usage
            if (
                blob.startswith("data:image")
                or blob.startswith("data:font")
                or "BEGIN CERTIFICATE" in blob
            ):
                continue

            ent = self._calculate_shannon_entropy(blob)
            # Multi-level decode: attempt up to 3 decode rounds
            decoded_payload: bytes | None = None
            current = blob
            for _level in range(3):
                try:
                    # Normalise URL-safe alphabet before decoding
                    standard = current.replace("-", "+").replace("_", "/")
                    # Pad to 4-byte boundary
                    pad = (4 - len(standard) % 4) % 4
                    decoded = base64.b64decode(standard + "=" * pad)
                    if len(decoded) > 10:
                        decoded_payload = decoded
                        # Try another round if result is still valid Base64
                        try:
                            current = decoded.decode("ascii", errors="strict")
                            if not re.match(r"^[A-Za-z0-9+/\-_\s=]+$", current):
                                break
                        except UnicodeDecodeError:
                            break
                except Exception:
                    break

            # Flag if: entropy >= 3.5 OR decoded content contains dangerous keywords
            dangerous = bool(decoded_payload and _DANGEROUS_DECODED.search(decoded_payload))
            if ent < 3.5 and not dangerous:
                continue

            severity = Severity.CRITICAL if dangerous else Severity.HIGH
            findings.append(
                Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=severity,
                    title="Base64 Encoded Payload Detected",
                    explain=(
                        "Found a Base64-encoded block that may contain a concealed "
                        "payload. Entropy: {:.2f}. Dangerous content: {}.".format(
                            ent, dangerous
                        )
                    ),
                    evidence={
                        "type": "base64",
                        "length": len(blob),
                        "entropy": round(ent, 2),
                        "dangerous_decoded": dangerous,
                        "malicious_text": blob[:250],
                    },
                    module=self.name,
                    confidence=0.95 if dangerous else 0.80,
                    # Only the *decoded-content-is-dangerous* path is
                    # definitive (CRITICAL severity, dangerous=True means the
                    # base64 decode contained shellcode markers, PE headers,
                    # PowerShell encoded commands, eval(atob), cmd.exe /c, etc).
                    # High-entropy alone (HIGH severity) is still REVIEW —
                    # any compressed/encrypted legitimate content has high
                    # entropy too.
                    verdict_class=(
                        VerdictClass.BLOCK if dangerous else VerdictClass.REVIEW
                    ),
                )
            )
            b64_reported = True

        # Check raw hex blobs from metadata (for PDF fallback)
        if doc.metadata and "hex_blobs" in doc.metadata:
            for blob in doc.metadata["hex_blobs"]:
                # Exclude OLE files (VBA macros) to avoid confusion with T2
                if blob.upper().startswith("D0CF11E0"):
                    continue
                # Exclude benign placeholder objects found in some datasets
                if blob.upper().startswith("454D4245"):
                    continue  # "EMBE" (EMBEDDED_PLACEHOLDER)
                # Exclude PDF digital-signature blobs (PKCS#7 SignedData).
                if _is_pkcs7_signature(blob):
                    continue

                if len(blob) > 1024:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.HIGH,
                            title="Large Hex Blob Detected in PDF",
                            explain=(
                                "Found a massive hexadecimal string in PDF structure."
                            ),
                            evidence={"type": "hex_blob", "length": len(blob), "malicious_text": blob[:250]},
                            module=self.name,
                            confidence=0.9,
                        )
                    )
                    break  # One is enough

        # 2. Hex Blobs in Text
        # Continuous stream of hex digits
        # Threshold: 256 bytes (512 chars)
        hex_blob_re = re.compile(r"(?:[0-9a-fA-F]{2}){256,}")
        for match in hex_blob_re.finditer(text):
            blob = match.group(0)
            if blob.upper().startswith("D0CF11E0"):
                continue  # OLE (VBA)
            if blob.upper().startswith("504B0304"):
                continue  # PK Zip (Office/Jar)
            if blob.upper().startswith("454D4245"):
                continue  # EMBEDDED_PLACEHOLDER
            if _is_pkcs7_signature(blob):
                continue  # PDF digital signature (PKCS#7 SignedData)

            findings.append(
                Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title="Large Hex Blob Detected",
                    explain=(
                        "Found a large hexadecimal string (>256 bytes), potentially "
                        "representing machine code or binary payload."
                    ),
                    evidence={"type": "hex", "length": len(blob), "malicious_text": blob[:250]},
                    module=self.name,
                    confidence=0.8,
                )
            )
            break

        # 3. Encoded Scripts (e.g. eval(atob(...)), or powershell -enc)
        # Simple heuristics
        suspicious_patterns = [
            (r"eval\s*\(\s*atob\s*\(", "JavaScript decoding execution"),
            (r"powershell.*-e(nc|ncodedcommand)\s+", "PowerShell Encoded Command"),
            (r"cmd\.exe\s+/c", "Command execution"),
        ]

        for pat, title in suspicious_patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                # H.3 (0.4.8): center the evidence on the match — the head of
                # the document said nothing about *what* command was found.
                snippet = text[max(0, m.start() - 60): m.end() + 190].strip()
                findings.append(
                    Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.CRITICAL,
                        title=f"Suspicious Script/Command: {title}",
                        explain=(
                            f"Detected pattern associated with script "
                            f"execution or payload delivery: {title}."
                        ),
                        evidence={"pattern": pat, "match": m.group(0)[:80], "malicious_text": snippet[:250]},
                        module=self.name,
                        confidence=0.95,
                        # eval(atob(...)), powershell -enc, cmd.exe /c have
                        # no legitimate use in document body text — definitive.
                        verdict_class=VerdictClass.BLOCK,
                    )
                )

        # 4. Hex-encoded binary file signatures in document text/metadata
        # Attackers embed PE (Windows), ELF (Linux) headers as hex strings
        # to evade text-based content filters while keeping payload accessible.
        all_text = text
        if doc.metadata:
            for key in ("keywords", "description", "comments"):
                val = doc.metadata.get(key, "")
                if val and isinstance(val, str):
                    all_text = all_text + " " + val

        BIN_HEX_SIGS = [
            (r"\b4[Dd]5[Aa]\b", "Windows PE executable (MZ header as hex)"),
            (r"\b7[Ff]45[Cc]46\b", "Linux ELF executable header as hex"),
        ]
        for pattern, label in BIN_HEX_SIGS:
            if re.search(pattern, all_text):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.HIGH,
                        title=f"Hex-Encoded Binary Signature: {label}",
                        explain=(
                            "Found hex-encoded binary file header in document "
                            "content. This pattern indicates an embedded executable "
                            "or binary payload concealed within document text."
                        ),
                        evidence={"signature": label},
                        module=self.name,
                        confidence=0.85,
                    )
                )
                break

        return findings

    @staticmethod
    def fast_scan(file_path: str, config: ScanConfig) -> List[Finding]:
        findings = []

        try:
            limit = 10 * 1024 * 1024
            # Quick check for binary signatures of executables
            # Limit to 10MB scan for embedded binaries.
            with open(file_path, "rb") as f:
                data = f.read(limit)

            # 1. OLE Object in PDF (Embedding Office docs in PDF)
            if file_path.lower().endswith(".pdf"):
                # OLE Header: D0 CF 11 E0
                offset = data.find(b"\xd0\xcf\x11\xe0")
                if offset != -1:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.HIGH,
                            title="OLE Object Detected in PDF",
                            explain=(
                                "Detected OLE binary header inside PDF file. "
                                "This is often used to embed malicious Office "
                                "documents or exploits."
                            ),
                            evidence={"offset": offset},
                            module="embedded_payload.fast",
                        )
                    )

            # 2. PE Executable Header (Windows Exe)
            # Look for "This program cannot be run in DOS mode" stub
            if b"This program cannot be run in DOS mode" in data:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.CRITICAL,
                        title="Embedded PE Executable Detected",
                        explain=(
                            "Found standard PE executable stub "
                            "('This program cannot be run in DOS mode'). "
                            "This indicates an embedded EXE/DLL."
                        ),
                        evidence={},
                        module="embedded_payload.fast",
                        # PE DOS stub embedded in a document — definitive.
                        verdict_class=VerdictClass.BLOCK,
                    )
                )

            # 3. ELF Header (Linux Exe)
            # \x7F ELF
            # Only flag if found AFTER index 0 or in a non-ELF file
            elf_idx = data.find(b"\x7fELF")
            if elf_idx != -1:
                is_elf_file = file_path.lower().endswith(".elf") or (
                    elf_idx == 0 and "." not in os.path.basename(file_path)
                )
                if not is_elf_file:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.HIGH,
                            title="Embedded ELF Binary Detected",
                            explain="Found ELF binary header embedded in document.",
                            evidence={"offset": elf_idx},
                            module="embedded_payload.fast",
                            # Linux binary embedded in a document — definitive.
                            verdict_class=VerdictClass.BLOCK,
                        )
                    )

            # D.15: Mach-O headers (Apple binaries) — 32/64/fat variants.
            # Only flag if NOT at offset 0 (a stand-alone Mach-O isn't a doc)
            # or if the file claims to be a document by extension.
            _MACHO_MAGICS = [
                (b"\xCE\xFA\xED\xFE", "Mach-O 32-bit"),
                (b"\xCF\xFA\xED\xFE", "Mach-O 64-bit"),
                (b"\xFE\xED\xFA\xCE", "Mach-O 32-bit (BE)"),
                (b"\xFE\xED\xFA\xCF", "Mach-O 64-bit (BE)"),
                (b"\xCA\xFE\xBA\xBE", "Mach-O fat binary"),
            ]
            doc_ext = file_path.lower().rsplit(".", 1)[-1] if "." in file_path else ""
            is_doc_ext = doc_ext in {
                "pdf", "docx", "pptx", "xlsx", "rtf", "html", "htm",
                "doc", "xls", "ppt", "csv", "odt", "ods", "odp",
            }
            for magic, label in _MACHO_MAGICS:
                idx = data.find(magic)
                if idx == -1:
                    continue
                # Java .class files start with CAFEBABE — exclude when
                # extension is .class.
                if magic == b"\xCA\xFE\xBA\xBE" and doc_ext == "class":
                    continue
                if idx == 0 and not is_doc_ext:
                    continue  # Stand-alone Mach-O — not a document
                findings.append(Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title=f"Embedded {label} Binary Detected",
                    explain=(
                        f"Found {label} magic bytes at offset {idx} inside a "
                        "document — embedded macOS executable / dropper."
                    ),
                    evidence={
                        "subtype": "macho_embedded",
                        "offset": idx,
                        "label": label,
                        "malicious_text": label,
                    },
                    confidence=0.85,
                    module="embedded_payload.fast",
                    # macOS binary embedded in a document — definitive.
                    verdict_class=VerdictClass.BLOCK,
                ))
                break

            # D.15: WebAssembly module (00 61 73 6D — "\\0asm")
            wasm_idx = data.find(b"\x00asm")
            if wasm_idx != -1 and wasm_idx > 0:
                findings.append(Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.MEDIUM,
                    title="Embedded WebAssembly Module",
                    explain=(
                        f"Found WebAssembly magic bytes at offset {wasm_idx}. "
                        "WASM modules can carry complex payloads that execute "
                        "in browser/runtime contexts."
                    ),
                    evidence={
                        "subtype": "wasm_embedded",
                        "offset": wasm_idx,
                        "malicious_text": "WebAssembly module",
                    },
                    confidence=0.75,
                    module="embedded_payload.fast",
                ))

            # D.15: ISO 9660 filesystem (CD001 at fixed offset 0x8001 in a true
            # ISO).  When found inside a non-ISO document it indicates an
            # embedded mountable image (CVE-2023-36884 phishing chain).
            iso_idx = data.find(b"CD001")
            if iso_idx != -1 and not file_path.lower().endswith((".iso", ".img")):
                # Verify it's at an ISO-plausible offset (>= 0x8000 / not text)
                if iso_idx >= 0x8000:
                    findings.append(Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.HIGH,
                        title="Embedded ISO 9660 Filesystem Image",
                        explain=(
                            f"ISO 9660 magic 'CD001' at offset {iso_idx} — "
                            "embedded mountable disc image. Used in CVE-2023-36884 "
                            "and follow-on phishing chains to bypass MOTW."
                        ),
                        evidence={
                            "subtype": "iso_embedded",
                            "offset": iso_idx,
                            "malicious_text": "ISO 9660 filesystem",
                        },
                        confidence=0.85,
                        module="embedded_payload.fast",
                        cve="CVE-2023-36884",
                        # CVE-2023-36884 / MOTW-bypass phishing chain pattern
                        # — definitive when found inside a document file.
                        verdict_class=VerdictClass.BLOCK,
                    ))

            # D.15: RAR archive header (Rar!\x1A\x07)
            rar_idx = data.find(b"Rar!\x1A\x07")
            if rar_idx != -1 and not file_path.lower().endswith(".rar"):
                findings.append(Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title="Embedded RAR Archive",
                    explain=(
                        f"RAR magic at offset {rar_idx} inside a non-RAR file. "
                        "Embedded archives are a common dropper carrier."
                    ),
                    evidence={
                        "subtype": "rar_embedded",
                        "offset": rar_idx,
                        "malicious_text": "RAR archive",
                    },
                    confidence=0.85,
                    module="embedded_payload.fast",
                ))

            # D.15: 7z archive header (37 7A BC AF 27 1C)
            sz_idx = data.find(b"\x37\x7A\xBC\xAF\x27\x1C")
            if sz_idx != -1 and not file_path.lower().endswith(".7z"):
                findings.append(Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title="Embedded 7z Archive",
                    explain=(
                        f"7z magic at offset {sz_idx} inside a non-7z file — "
                        "embedded archive payload carrier."
                    ),
                    evidence={
                        "subtype": "7z_embedded",
                        "offset": sz_idx,
                        "malicious_text": "7z archive",
                    },
                    confidence=0.85,
                    module="embedded_payload.fast",
                ))

            # 4. Appended-data detection (item 0.13)
            # Data after a known end-of-file marker is a steganographic payload carrier.
            TAIL_SIZE = 1024
            with open(file_path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()
                if file_size > TAIL_SIZE:
                    f.seek(-TAIL_SIZE, 2)
                    tail = f.read(TAIL_SIZE)
                else:
                    f.seek(0)
                    tail = f.read()

            # PDF: data after %%EOF
            if file_path.lower().endswith(".pdf"):
                eof_idx = tail.rfind(b"%%EOF")
                if eof_idx != -1:
                    after = tail[eof_idx + 5:].strip()
                    if after and not after.isspace():
                        findings.append(Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.MEDIUM,
                            title="PDF: Data Appended After %%EOF",
                            explain=(
                                "Non-whitespace data was found after the PDF %%EOF "
                                "marker. This is a common technique for concealing "
                                "payloads in document files."
                            ),
                            evidence={"bytes_after_eof": len(after)},
                            confidence=0.80,
                            module="embedded_payload.fast",
                        ))

            # JPEG: data after FF D9 (EOI). MUST be gated on file extension —
            # the byte pair 0xFF 0xD9 routinely appears in PDF compressed
            # streams (FlateDecode output), font data, and embedded image
            # streams. Without this guard, every PDF that happens to contain
            # 0xFF 0xD9 in its last 1024 bytes false-fires T7 MEDIUM.
            if file_path.lower().endswith((".jpg", ".jpeg")):
                eoi = tail.rfind(b"\xff\xd9")
                if eoi != -1 and eoi < len(tail) - 2:
                    after = tail[eoi + 2:].strip(b"\x00\xff\n\r ")
                    if after:
                        findings.append(Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.MEDIUM,
                            title="JPEG: Data Appended After EOI Marker",
                            explain=(
                                "Non-zero data found after the JPEG End-of-Image "
                                "marker (0xFF 0xD9) — a common steganographic carrier."
                            ),
                            evidence={"bytes_after_eoi": len(after)},
                            confidence=0.75,
                            module="embedded_payload.fast",
                        ))

            # PNG: data after IEND chunk. Same reason as the JPEG check above —
            # the IEND signature bytes (`IEND\xae\x42\x60\x82`) can appear in
            # compressed streams or embedded-image data inside non-PNG files.
            if file_path.lower().endswith(".png"):
                iend = tail.rfind(b"\x49\x45\x4e\x44\xae\x42\x60\x82")
                if iend != -1 and iend < len(tail) - 8:
                    after = tail[iend + 8:].strip(b"\x00\n\r ")
                    if after:
                        findings.append(Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.MEDIUM,
                            title="PNG: Data Appended After IEND Chunk",
                            explain=(
                                "Non-zero data found after the PNG IEND chunk — "
                                "a common steganographic payload carrier."
                            ),
                            evidence={"bytes_after_iend": len(after)},
                            confidence=0.75,
                            module="embedded_payload.fast",
                        ))

        except Exception as e:
            logger.warning("Embedded payload fast scan error", error=str(e))
        return findings
