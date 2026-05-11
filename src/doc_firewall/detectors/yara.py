from __future__ import annotations
import os
from typing import List, Optional
from .base import Detector
from ..analyzers.base import ParsedDocument
from ..config import ScanConfig
from ..report import Finding
from ..enums import ThreatID, Severity
from ..logger import get_logger

logger = get_logger()

try:
    import yara
except ImportError:
    yara = None


def _compile_rules(user_path: Optional[str], include_builtin: bool) -> "yara.Rules | None":
    """Compile YARA rules from optional user path and/or built-in ruleset.

    Returns a compiled Rules object, or None when yara-python is missing or
    no rules are configured.
    """
    if yara is None:
        return None

    sources: dict[str, str] = {}

    if include_builtin:
        from ..rules import DOCUMENT_MALWARE_RULES
        if os.path.isfile(DOCUMENT_MALWARE_RULES):
            sources["builtin"] = DOCUMENT_MALWARE_RULES

    if user_path and os.path.isfile(user_path):
        sources["custom"] = user_path

    if not sources:
        return None

    try:
        if len(sources) == 1:
            return yara.compile(filepath=next(iter(sources.values())))
        # Compile multiple files together
        return yara.compile(filepaths=sources)
    except Exception as exc:
        logger.warning("YARA rule compilation failed: %s", exc)
        return None


class YaraDetector(Detector):
    name = "yara"

    def run(self, doc: ParsedDocument, config: ScanConfig) -> List[Finding]:
        # EICAR test string check always runs regardless of enable_yara setting
        eicar_signature = (
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )

        findings = []
        text = doc.text or ""

        # Combine all metadata into a searchable string
        meta_text = ""
        if doc.metadata:
            meta_text = " ".join(str(v) for v in doc.metadata.values())

        # Check text and metadata
        if eicar_signature in text or eicar_signature in meta_text:
            findings.append(
                Finding(
                    threat_id=ThreatID.T1_MALWARE,
                    severity=Severity.CRITICAL,
                    title="Malware Signature Detected (EICAR)",
                    explain="Found EICAR test string in document text or metadata.",
                    evidence={"signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
                    module=self.name,
                )
            )
            return findings  # CRITICAL stops scan usually

        if not config.enable_yara:
            return findings

        include_builtin = getattr(config, "enable_builtin_yara_rules", False)
        compiled = _compile_rules(config.yara_rules_path, include_builtin)
        if compiled is None:
            if yara is None:
                logger.debug("yara-python not installed; skipping YARA scan")
            return findings

        try:
            # Scan logical text first (fast)
            text_matches = compiled.match(data=text)
            for m in text_matches:
                findings.append(
                    Finding(
                        threat_id=ThreatID.T1_MALWARE,
                        severity=Severity.CRITICAL,
                        title=f"YARA Rule Match (Text): {m.rule}",
                        explain=f"Document text matched YARA rule '{m.rule}'",
                        evidence={"rule": m.rule, "tags": m.tags, "meta": m.meta},
                        module=f"{self.name}.text",
                        cve=m.meta.get("cve") or None,
                        mitre_technique=m.meta.get("mitre") or None,
                        attack_objective=m.meta.get("description") or None,
                    )
                )

            # Scan binary file if available (comprehensive)
            if doc.file_path and os.path.isfile(doc.file_path):
                file_matches = compiled.match(filepath=doc.file_path)
                for m in file_matches:
                    # Deduplicate if same rule matched both
                    if not any(f.evidence.get("rule") == m.rule for f in findings):
                        findings.append(
                            Finding(
                                threat_id=ThreatID.T1_MALWARE,
                                severity=Severity.CRITICAL,
                                title=f"YARA Rule Match (Binary): {m.rule}",
                                explain=f"File binary matched YARA rule '{m.rule}'",
                                evidence={
                                    "rule": m.rule,
                                    "tags": m.tags,
                                    "meta": m.meta,
                                    "malicious_text": str(m.strings[0][2][:250]) if getattr(m, "strings", None) and len(m.strings) > 0 else ""
                                },
                                module=f"{self.name}.binary",
                                cve=m.meta.get("cve") or None,
                                mitre_technique=m.meta.get("mitre") or None,
                                attack_objective=m.meta.get("description") or None,
                            )
                        )
        except Exception as e:
            logger.debug("Error running YARA scan: %s", e)

        return findings
