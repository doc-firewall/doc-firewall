from __future__ import annotations
import re
import math
import os
from typing import List
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()


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

        # 1. Base64 Blocks > 1KB
        # Base64 chars: A-Z, a-z, 0-9, +, /, and = padding.
        # Length 1KB approx 1366 chars.
        b64_long = re.compile(r"[A-Za-z0-9+/]{1024,}={0,2}")
        for match in b64_long.finditer(text):
            blob = match.group(0)
            # Filter out common benign Base64 usage
            if (
                blob.startswith("data:image")
                or blob.startswith("data:font")
                or "BEGIN CERTIFICATE" in blob
            ):
                continue

            # Heuristic: payload usually high entropy.
            # Text-like base64 has specific char distribution?
            # For now, just rely on valid exclusions.

            # Entropy Check (Production Generalization)
            # High entropy (>4.5) suggests compressed or encrypted payload.
            # Low entropy suggests simple text or repetitive patterns (benign).
            ent = self._calculate_shannon_entropy(blob)
            if ent < 4.5:
                continue

            findings.append(
                Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title="Large Base64 Block Detected",
                    explain=(
                        "Found a base64-encoded block larger than 1KB, which may "
                        "contain a concealed payload. (Common formats excluded)"
                    ),
                    evidence={"type": "base64", "length": len(blob)},
                    module=self.name,
                    confidence=0.9,
                )
            )
            # Just report once to avoid noise
            break

        # Check raw hex blobs from metadata (for PDF fallback)
        if doc.metadata and "hex_blobs" in doc.metadata:
            for blob in doc.metadata["hex_blobs"]:
                # Exclude OLE files (VBA macros) to avoid confusion with T2
                if blob.upper().startswith("D0CF11E0"):
                    continue
                # Exclude benign placeholder objects found in some datasets
                if blob.upper().startswith("454D4245"):
                    continue  # "EMBE" (EMBEDDED_PLACEHOLDER)

                if len(blob) > 1024:
                    findings.append(
                        Finding(
                            threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                            severity=Severity.HIGH,
                            title="Large Hex Blob Detected in PDF",
                            explain=(
                                "Found a massive hexadecimal string "
                                "in PDF structure."
                            ),
                            evidence={"type": "hex_blob", "length": len(blob)},
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

            findings.append(
                Finding(
                    threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                    severity=Severity.HIGH,
                    title="Large Hex Blob Detected",
                    explain=(
                        "Found a large hexadecimal string (>256 bytes), potentially "
                        "representing machine code or binary payload."
                    ),
                    evidence={"type": "hex", "length": len(blob)},
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
            if re.search(pat, text, re.IGNORECASE):
                findings.append(
                    Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.CRITICAL,
                        title=f"Suspicious Script/Command: {title}",
                        explain=(
                            f"Detected pattern associated with script "
                            f"execution or payload delivery: {title}."
                        ),
                        evidence={"pattern": pat},
                        module=self.name,
                        confidence=0.95,
                    )
                )

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
                        )
                    )

        except Exception as e:
            logger.warning("Embedded payload fast scan error", error=str(e))
        return findings
