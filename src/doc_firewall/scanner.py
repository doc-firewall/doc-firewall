from __future__ import annotations
import os
import asyncio
import tarfile
import tempfile
import zipfile as _zipfile
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from .config import ScanConfig
from .enums import ThreatID, Severity, Verdict, VerdictClass
from .policy import Policy, PolicyEngine
from .report import ScanReport, Finding
from .risk_model import RiskModel
from .capabilities import build_coverage_report
from .detectors.explanations import enrich_findings
from .detectors.evidence_contract import apply_evidence_contract
from .analyzers.pdf.fast_scan import fast_scan_pdf
from .analyzers.docx.fast_scan import fast_scan_docx
from .analyzers.pptx.fast_scan import fast_scan_pptx
from .analyzers.xlsx.fast_scan import fast_scan_xlsx
from .analyzers.rtf.fast_scan import fast_scan_rtf
from .analyzers.html.fast_scan import fast_scan_html
from .analyzers.ole.fast_scan import fast_scan_ole, _CFB_MAGIC
from .analyzers.csv.fast_scan import fast_scan_csv
from .analyzers.odf.fast_scan import fast_scan_odf
from .analyzers.pdf.parser import parse_pdf, ParsedDocument
from .analyzers.docx.parser import parse_docx
from .analyzers.pptx.parser import parse_pptx
from .analyzers.xlsx.parser import parse_xlsx
from .analyzers.rtf.parser import parse_rtf
from .analyzers.html.parser import parse_html
from .analyzers.ole.parser import parse_ole
from .analyzers.csv.parser import parse_csv
from .analyzers.odf.parser import parse_odf

# format checks
from .analyzers.pdf.active_content import detect_pdf_active_content
from .analyzers.pdf.obfuscation import detect_pdf_obfuscation
from .analyzers.docx.external_refs import detect_docx_external_refs
from .analyzers.docx.ole import detect_docx_ole_objects
from .analyzers.docx.macros import detect_docx_macros
from .analyzers.pptx.external_refs import detect_pptx_external_refs
from .analyzers.pptx.macros import detect_pptx_macros
from .analyzers.xlsx.external_refs import detect_xlsx_external_refs
from .analyzers.xlsx.macros import detect_xlsx_macros
from .detectors.embedded_payload import EmbeddedPayloadDetector
from .detectors.dos_pdf import PdfDoSDetector
from .detectors.metadata_injection import MetadataInjectionDetector
from .detectors.ats_manipulation import ATSManipulationDetector
from .detectors.prompt_injection import PromptInjectionDetector
from .detectors.ranking_manipulation import RankingManipulationDetector
from .detectors.yara import YaraDetector
from .detectors.text_obfuscation import TextObfuscationDetector
from .detectors.hidden_text import HiddenTextDetector

from .detectors.advanced_prompt_injection import AdvancedPromptInjectionDetector
from .detectors.advanced_ats_manipulation import AdvancedATSNLPDetector
from .detectors.credential_leakage import CredentialLeakageDetector
from .detectors.injection_nn import InjectionNNDetector
from .detectors.steganography import SteganographyDetector
from .detectors.ocr_injection import OCRInjectionDetector
from .detectors.indirect_injection import IndirectInjectionDetector
from .detectors.rag_poisoning import RAGPoisoningDetector
from .detectors.social_engineering import SocialEngineeringDetector
from .detectors.pii import PiiDetector
from .detectors.injection_perplexity import InjectionPerplexityDetector
from .detectors.media_metadata import MediaMetadataDetector

from .utils.circuit_breaker import CircuitBreaker, CircuitOpenError
from .utils.hashing import sha256_file
from .utils.mime import guess_file_type, is_macro_template
from .utils.timeouts import Timer
from .logger import get_logger

logger = get_logger()


_MAGIC_BYTES = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip",  # Generic ZIP — probe inner structure to refine
    b"{\\rtf": "rtf",      # RTF documents start with {\rtf
    # D.2: legacy Office binary formats — all share the CFB header.  The
    # specific format (.doc / .xls / .ppt) is resolved by inspecting the
    # OLE stream layout in the analyzer.
    _CFB_MAGIC: "ole",
}

_ZIP_INNER_SIGNATURES: list[tuple[str, str]] = [
    ("word/document.xml", "docx"),
    ("ppt/presentation.xml", "pptx"),
    ("xl/workbook.xml", "xlsx"),
    # E.2: OpenDocument formats — all share the `mimetype` part at archive
    # offset 0; we probe for the format-specific body file.
    ("content.xml", "odf"),  # generic ODF — refined by extension if needed
]


def _detect_file_type_by_magic(path: str) -> str:
    """Detect file type using magic bytes; for ZIP-based formats, probe inner
    content to distinguish docx / pptx / xlsx."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        for magic, ftype in _MAGIC_BYTES.items():
            if header.startswith(magic):
                if ftype == "zip":
                    # ZIP-based: peek inside to differentiate Office formats
                    try:
                        import zipfile as _zf

                        with _zf.ZipFile(path, "r") as zf:
                            names = set(zf.namelist())
                            for inner, detected in _ZIP_INNER_SIGNATURES:
                                if inner in names:
                                    # E.2: refine generic "odf" → specific
                                    # variant via the mimetype file.
                                    if detected == "odf" and "mimetype" in names:
                                        try:
                                            mt = zf.read("mimetype").decode(
                                                "ascii", errors="replace"
                                            ).strip()
                                            if "spreadsheet" in mt:
                                                return "odf.sheet"
                                            if "presentation" in mt:
                                                return "odf.presentation"
                                            if "text" in mt:
                                                return "odf.text"
                                        except Exception:
                                            pass
                                        return "odf.text"
                                    return detected
                    except Exception:
                        pass
                    return "zip"  # Unknown ZIP format
                if ftype == "ole":
                    # D.2: distinguish legacy .doc / .xls / .ppt by extension.
                    # The OLE stream layout could resolve this authoritatively
                    # but the extension is reliable in practice and avoids a
                    # second open+parse just for type classification.
                    ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
                    if ext in {"doc", "dot"}:
                        return "ole.doc"
                    if ext in {"xls", "xlt"}:
                        return "ole.xls"
                    if ext in {"ppt", "pot"}:
                        return "ole.ppt"
                    return "ole"
                return ftype
    except OSError:
        pass
    return "unknown"


class Scanner:
    def __init__(
        self,
        config: Optional[ScanConfig] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.risk_model = RiskModel(self.config)
        self._executor = ThreadPoolExecutor(
            max_workers=getattr(self.config, "max_workers", 4)
        )

        # Policy engine — built from config.policy_path if not supplied explicitly
        if policy_engine is not None:
            self._policy_engine: Optional[PolicyEngine] = policy_engine
        elif self.config.policy_path:
            self._policy_engine = PolicyEngine(self.config.policy_path)
        else:
            self._policy_engine = None

        # Model integrity — verify model files before any detector loads them
        if self.config.verify_model_integrity and self.config.model_integrity_manifest_path:
            from .security.model_integrity import ModelIntegrityChecker
            checker = ModelIntegrityChecker(self.config.model_integrity_manifest_path)
            for model_path in self._model_paths():
                checker.verify(model_path)

        # Initialize detectors
        self.detectors = [
            EmbeddedPayloadDetector(),
            PdfDoSDetector(),  # Deep scan for DoS
            MetadataInjectionDetector(),
            ATSManipulationDetector(),
            PromptInjectionDetector(),
            RankingManipulationDetector(),
            YaraDetector(),
            TextObfuscationDetector(),
            HiddenTextDetector(),
            AdvancedPromptInjectionDetector(),
            AdvancedATSNLPDetector(),
            CredentialLeakageDetector(),
            InjectionNNDetector(),
            SteganographyDetector(),
            OCRInjectionDetector(),
            IndirectInjectionDetector(),
            RAGPoisoningDetector(),
            SocialEngineeringDetector(),
            PiiDetector(),
            InjectionPerplexityDetector(),
            MediaMetadataDetector(),
        ]

        # G.4: eagerly build expensive per-config detector state (compiled
        # regex sets, Aho-Corasick automata) at construction time so the
        # first scan isn't materially slower than steady-state. A failing
        # prepare() must never block Scanner construction — detectors keep a
        # lazy fallback in run().
        for det in self.detectors:
            try:
                det.prepare(self.config)
            except Exception as exc:
                logger.warning(
                    "Detector prepare() failed; will lazy-init on first scan",
                    detector=det.name,
                    error=str(exc),
                )

        # One circuit breaker per detector — persists across scan() calls so
        # failures accumulate and a consistently-broken detector eventually
        # trips open for the cooldown period.
        self._breakers: dict[str, CircuitBreaker] = {
            det.name: CircuitBreaker(
                name=det.name,
                max_failures=self.config.limits.circuit_breaker_max_failures,
                cooldown_s=float(self.config.limits.circuit_breaker_cooldown_s),
            )
            for det in self.detectors
        }

        # H.11 (0.4.8): coverage transparency. Build the capability report
        # once and warn loudly — exactly once per Scanner — when the scanner
        # is running with no active detection for an ML-dependent threat
        # (T1 malware signatures / T4 semantic-OCR-BERT injection). A
        # security scanner must not silently under-deliver on its promises.
        self._coverage = build_coverage_report(self.config)
        if self._coverage.degraded:
            logger.warning(
                "doc-firewall reduced-coverage mode",
                degraded_threats=self._coverage.degraded_threats,
                summary=self._coverage.summary_line(),
            )

    def _model_paths(self) -> list[str]:
        """Collect configured ML model paths for integrity pre-check."""
        paths = []
        if self.config.bert_model_path:
            paths.append(self.config.bert_model_path)
        if self.config.nn_model_name and os.path.isdir(self.config.nn_model_name):
            paths.append(self.config.nn_model_name)
        return [p for p in paths if os.path.exists(p)]

    def _scan_archive(
        self,
        archive_path: str,
        parent_report: ScanReport,
        depth: int = 0,
    ) -> None:
        """Unpack a ZIP or tar archive and recursively scan each member (B.7).

        Findings from sub-scans are merged into *parent_report* with
        ``evidence["archive_member"]`` indicating the originating path.
        Stops at ``limits.max_archive_depth`` recursion levels and
        ``limits.max_archive_members`` per archive.
        """
        if depth >= self.config.limits.max_archive_depth:
            parent_report.add(Finding(
                threat_id=ThreatID.T6_DOS,
                severity=Severity.MEDIUM,
                title="Archive Recursion Depth Limit Reached",
                explain=(
                    f"Archive nesting exceeded {self.config.limits.max_archive_depth} "
                    "levels. Remaining contents were not scanned."
                ),
                evidence={"archive_path": archive_path, "depth": depth},
                module="scanner.archive",
            ))
            return

        max_mb = self.config.limits.max_mb * 1024 * 1024
        max_members = self.config.limits.max_archive_members

        with tempfile.TemporaryDirectory(prefix="docfw_arc_") as tmpdir:
            members_extracted = 0
            try:
                if tarfile.is_tarfile(archive_path):
                    with tarfile.open(archive_path, "r:*") as tf:
                        for member in tf.getmembers():
                            if members_extracted >= max_members:
                                break
                            if member.size > max_mb:
                                parent_report.add(Finding(
                                    threat_id=ThreatID.T6_DOS,
                                    severity=Severity.MEDIUM,
                                    title="Archive Member Exceeds Size Limit",
                                    explain=f"Member '{member.name}' exceeds scan limit.",
                                    evidence={"member": member.name, "size": member.size},
                                    module="scanner.archive",
                                ))
                                continue
                            if not member.isfile():
                                continue
                            tf.extract(member, path=tmpdir, filter="data")
                            members_extracted += 1
                elif _zipfile.is_zipfile(archive_path):
                    with _zipfile.ZipFile(archive_path, "r") as zf:
                        for info in zf.infolist():
                            if members_extracted >= max_members:
                                break
                            if info.file_size > max_mb:
                                parent_report.add(Finding(
                                    threat_id=ThreatID.T6_DOS,
                                    severity=Severity.MEDIUM,
                                    title="Archive Member Exceeds Size Limit",
                                    explain=f"Member '{info.filename}' exceeds scan limit.",
                                    evidence={"member": info.filename, "size": info.file_size},
                                    module="scanner.archive",
                                ))
                                continue
                            if info.filename.endswith("/"):
                                continue
                            zf.extract(info, path=tmpdir)
                            members_extracted += 1
                else:
                    return  # Not a recognized archive format
            except Exception as exc:
                logger.debug("Archive extraction error: %s", exc)
                return

            # Scan each extracted file
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    member_path = os.path.join(root, fname)
                    relative = os.path.relpath(member_path, tmpdir)
                    try:
                        sub_report = self.scan(member_path)
                        for finding in sub_report.findings:
                            # Tag with originating archive member path
                            finding.evidence = dict(finding.evidence or {})
                            finding.evidence["archive_member"] = relative
                            parent_report.add(finding)
                        # Recurse into nested archives
                        member_ftype = _detect_file_type_by_magic(member_path)
                        if member_ftype == "zip" and self.config.enable_archive_scan:
                            self._scan_archive(member_path, parent_report, depth + 1)
                    except Exception as exc:
                        logger.debug("Sub-scan error for %s: %s", relative, exc)

    def _apply_coverage(self, report: ScanReport) -> None:
        """H.11 (0.4.8): attach the coverage report and, when the caller has
        asked to fail closed on missing capability, add an escalation
        finding so the verdict reflects that the document was checked with
        reduced coverage. Must run BEFORE get_verdict()."""
        cov = self._coverage
        report.coverage = cov.to_dict()

        required = set(getattr(self.config, "required_capabilities", []) or [])
        missing_required = sorted(
            c.key for c in cov.capabilities if c.key in required and not c.active
        )
        fail_full = getattr(self.config, "require_full_coverage", False) and cov.degraded

        if not (missing_required or fail_full):
            return

        reasons: list[str] = []
        if fail_full:
            reasons.append(
                "no active detection capability for "
                + ", ".join(cov.degraded_threats)
            )
        if missing_required:
            reasons.append("required capabilities inactive: " + ", ".join(missing_required))

        report.add(Finding(
            threat_id=ThreatID.T1_MALWARE if "T1" in cov.degraded_threats
            else ThreatID.T4_PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            title="Scan ran with reduced detection coverage",
            explain=(
                "This document was scanned with one or more promised detection "
                "capabilities INACTIVE, so a clean verdict cannot be fully "
                "trusted. " + "; ".join(reasons) + "."
            ),
            evidence={
                "subtype": "reduced_coverage",
                "degraded_threats": cov.degraded_threats,
                "missing_required": missing_required,
                "inactive_capabilities": [
                    {"key": c.key, "label": c.label, "remediation": c.remediation}
                    for c in cov.inactive
                ],
                "evidence_unavailable_reason": (
                    "the detectors that would produce content-level evidence "
                    "for these threats are not installed/enabled"
                ),
                "debug_steps": [
                    c.remediation for c in cov.inactive if c.key in required
                ] or [c.remediation for c in cov.inactive],
            },
            module="scanner.coverage",
            confidence=0.5,
            # Operational: escalates verdict to FLAG, never BLOCK on its own.
            verdict_class=VerdictClass.REVIEW,
        ))

    def _apply_unscannable_policy(self, report: ScanReport) -> None:
        """H.13 (0.4.8): apply the configured verdict for content the scanner
        cannot inspect (encrypted PDF/Office/archive). The analyzers tag such
        findings with evidence['subtype']=='encrypted_unscannable'; policy is
        applied centrally here so it lives in one place.

          allow → INFO (recorded, never affects verdict)
          warn  → REVIEW (FLAG; the default)
          block → BLOCK (fail closed)
        """
        policy = getattr(self.config, "on_unscannable_verdict", "warn")
        if policy == "warn":
            return  # default REVIEW class already FLAGs
        for f in report.findings:
            if (f.evidence or {}).get("subtype") != "encrypted_unscannable":
                continue
            if policy == "block":
                f.verdict_class = VerdictClass.BLOCK
                f.severity = Severity.HIGH
            elif policy == "allow":
                f.verdict_class = VerdictClass.INFO

    def _timeout_finding(self, stage: str, timeout_ms: int) -> Finding:
        """H.6 (0.4.8): a stage timeout leaves the scan incomplete — the
        document was never fully checked, so it must not silently ALLOW.
        Emits an operational finding (NOT a DoS-attack claim) that escalates
        the verdict to FLAG, or BLOCK when ``on_timeout_verdict='block'``."""
        fail_closed = (
            getattr(self.config, "on_timeout_verdict", "warn") == "block"
        )
        return Finding(
            threat_id=ThreatID.T6_DOS,
            severity=Severity.MEDIUM,
            title=f"Scan incomplete — {stage} stage timed out",
            explain=(
                f"The {stage} stage exceeded its {timeout_ms / 1000:.0f}s "
                "budget, so this document was NOT fully scanned. This is an "
                "operational signal (large/complex documents under heavy ML "
                "configs can exceed the budget), not evidence the document "
                "is malicious — but an incomplete scan must not pass "
                "silently."
            ),
            evidence={
                "subtype": "scan_timeout",
                "stage": stage,
                "timeout_ms": timeout_ms,
                "evidence_unavailable_reason": (
                    f"the {stage} stage timed out before analysis finished; "
                    "no content-level evidence could be produced"
                ),
                "debug_steps": [
                    "Re-scan with a larger budget: set "
                    f"DOC_FIREWALL_LIMITS_{stage.upper()}_TIMEOUT_MS to a "
                    "higher value (or pass limits={...} in ScanConfig).",
                    "Re-scan with profile='lenient' to disable the heavy ML "
                    "detectors and isolate which stage is slow.",
                    "Check report.timings_ms to see where the time went.",
                ],
            },
            module=f"stage.{stage}",
            confidence=0.5,
            verdict_class=(
                VerdictClass.BLOCK if fail_closed else VerdictClass.REVIEW
            ),
        )

    async def scan_async(
        self,
        file_path: str,
        policy_name: Optional[str] = None,
    ) -> ScanReport:
        file_path = os.path.abspath(file_path)

        # Security: Validate path resolves to a regular file
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Not a regular file: {file_path}")
        real_path = os.path.realpath(file_path)
        if real_path != file_path and not os.path.isfile(real_path):
            raise ValueError("Symbolic link target does not exist")

        # Basic File info
        try:
            size_bytes = os.path.getsize(file_path)
            # Guard against OOM: reject excessively large files before hashing
            hard_limit = self.config.limits.max_mb * 1024 * 1024 * 2
            if size_bytes > hard_limit:
                raise ValueError(
                    f"File size ({size_bytes} bytes) exceeds hashing limit"
                )

            sha = sha256_file(file_path)

            # Determine file type by extension, then verify with magic bytes
            ftype = guess_file_type(file_path)
            magic_type = _detect_file_type_by_magic(file_path)
            if ftype != "unknown" and magic_type != "unknown" and ftype != magic_type:
                logger.warning(
                    "Extension/magic-byte mismatch",
                    extension_type=ftype,
                    magic_type=magic_type,
                )
                ftype = magic_type  # Trust magic bytes over extension
            elif ftype == "unknown" and magic_type != "unknown":
                ftype = magic_type

        except Exception as e:
            logger.error("Pre-flight check failed", file=file_path, error=str(e))
            raise

        # ── Policy resolution ────────────────────────────────────────────────
        effective_policy: Optional[Policy] = None
        if self._policy_engine is not None:
            effective_policy = self._policy_engine.get_for_file(
                file_path,
                policy_name=policy_name or self.config.policy_name,
            )

        log_ctx = logger.bind(
            file_path=file_path,
            sha256=sha,
            file_type=ftype,
            policy=effective_policy.name if effective_policy else None,
        )
        log_ctx.info("Starting scan")

        report = ScanReport(
            file_path=file_path, file_type=ftype, sha256=sha, size_bytes=size_bytes
        )

        if effective_policy is not None:
            report.metadata["policy"] = effective_policy.name

        # Deny list — instant BLOCK without scanning
        if effective_policy and sha.lower() in effective_policy.deny_hashes:
            log_ctx.warning("File matched policy deny list")
            report.add(
                Finding(
                    threat_id=ThreatID.T1_MALWARE,
                    severity=Severity.CRITICAL,
                    title="Denied by policy",
                    explain=f"SHA-256 {sha[:16]}… is on the deny list for policy '{effective_policy.name}'.",
                    module="policy.deny_list",
                    confidence=1.0,
                    # Explicit deny-list match — definitive.
                    verdict_class=VerdictClass.BLOCK,
                )
            )
            report.risk_score = 1.0
            report.verdict = Verdict.BLOCK
            return report

        # Allow list — skip all scanning, instant ALLOW
        if effective_policy and sha.lower() in effective_policy.allow_hashes:
            log_ctx.info("File matched policy allow list — scan skipped")
            report.metadata["allow_list_match"] = True
            report.risk_score = 0.0
            report.verdict = Verdict.ALLOW
            return report

        # --- STAGE 1: FAST SCAN ---
        size_mb = size_bytes / (1024 * 1024)
        if size_mb > self.config.limits.max_mb:
            log_ctx.warning("File size exceeded", size_mb=size_mb)
            report.add(
                Finding(
                    threat_id=ThreatID.T6_DOS,
                    severity=Severity.HIGH,
                    title="File exceeds size limit",
                    explain=(
                        f"File is {size_mb:.2f} MB, "
                        f"limit is {self.config.limits.max_mb} MB."
                    ),
                    evidence={
                        "size_mb": size_mb,
                        "limit_mb": self.config.limits.max_mb,
                    },
                    module="preflight",
                )
            )
            report.risk_score = self.risk_model.calculate_risk(report.findings)
            enrich_findings(report.findings)
            apply_evidence_contract(report.findings, report.file_type, report.file_path)
            self._apply_coverage(report)
            self._apply_unscannable_policy(report)
            report.verdict = self.risk_model.get_verdict(report.risk_score, report.findings)
            return report  # Early exit

        fast_findings = []
        loop = asyncio.get_running_loop()

        with Timer() as t:

            def _run_fast_scan():
                findings = []
                # 1. Embedded Payload Fast Scan
                if self.config.enable_embedded_content_checks:
                    findings.extend(
                        EmbeddedPayloadDetector.fast_scan(file_path, self.config)
                    )

                # 2. Existing Fast Scans
                if "pdf" in ftype and self.config.enable_pdf:
                    findings.extend(fast_scan_pdf(file_path, self.config))
                elif ftype == "docx" and self.config.enable_docx:
                    findings.extend(fast_scan_docx(file_path, self.config))
                elif ftype == "pptx" and self.config.enable_pptx:
                    findings.extend(fast_scan_pptx(file_path, self.config))
                elif ftype == "xlsx" and self.config.enable_xlsx:
                    findings.extend(fast_scan_xlsx(file_path, self.config))
                elif ftype == "rtf" and self.config.enable_rtf:
                    findings.extend(fast_scan_rtf(file_path, self.config))
                elif ftype == "html" and self.config.enable_html:
                    findings.extend(fast_scan_html(file_path, self.config))
                elif ftype.startswith("ole") and getattr(
                    self.config, "enable_legacy_office", True
                ):
                    findings.extend(fast_scan_ole(file_path, self.config))
                elif ftype == "csv" and getattr(
                    self.config, "enable_csv", True
                ):
                    findings.extend(fast_scan_csv(file_path, self.config))
                elif ftype.startswith("odf.") and getattr(
                    self.config, "enable_odf", True
                ):
                    findings.extend(fast_scan_odf(file_path, self.config))
                elif ftype == "zip" and self.config.enable_archive_scan:
                    # B.7: Generic ZIP — not an Office format. Unpack and
                    # recursively scan each member. Findings are merged back
                    # into this report after the fast scan returns.
                    findings.append(Finding(
                        threat_id=ThreatID.T7_EMBEDDED_PAYLOAD,
                        severity=Severity.LOW,
                        title="Archive Container Detected",
                        explain=(
                            "File is a plain ZIP archive (not an Office format). "
                            "Contents will be recursively scanned."
                        ),
                        evidence={"file_type": "zip"},
                        confidence=0.50,
                        module="scanner.archive",
                    ))

                # 3. New DoS Fast Checks
                if "pdf" in ftype and self.config.enable_pdf:
                    findings.extend(PdfDoSDetector.fast_scan(file_path, self.config))

                # 4. Macro-enabled template extension — elevated scrutiny (item 0.12)
                if self.config.enable_active_content_checks and is_macro_template(file_path):
                    from .report import Finding as _Finding
                    from .enums import ThreatID as _TID, Severity as _Sev
                    findings.append(_Finding(
                        threat_id=_TID.T2_ACTIVE_CONTENT,
                        severity=_Sev.MEDIUM,
                        title="Macro-Enabled Template File",
                        explain=(
                            "File extension indicates a macro-enabled template "
                            "(.dotm/.xltm/.potm/.xlsm/.pptm). These formats execute "
                            "macros on open by design and carry elevated risk. "
                            "Suppress via allow-list if the file is trusted."
                        ),
                        evidence={"extension": file_path.rsplit(".", 1)[-1].lower()},
                        confidence=0.80,
                        module="scanner.macro_template",
                    ))

                return findings

            try:
                fast_findings = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, _run_fast_scan),
                    timeout=self.config.limits.fast_scan_timeout_ms / 1000.0,
                )
            except asyncio.TimeoutError:
                log_ctx.error("Fast scan timed out — scan incomplete")
                report.metadata.setdefault("timed_out_stages", []).append("fast_scan")
                report.add(self._timeout_finding(
                    "fast_scan", self.config.limits.fast_scan_timeout_ms
                ))
            except Exception as e:
                log_ctx.error("Fast scan error", error=str(e))

        report.timings_ms["fast_scan"] = t.duration_ms
        report.findings.extend(fast_findings)

        # B.7: Recursively scan plain ZIP archives — run synchronously in executor
        # so we reuse the existing scan() path for each extracted member.
        if ftype == "zip" and self.config.enable_archive_scan:
            await loop.run_in_executor(
                self._executor, self._scan_archive, file_path, report, 0
            )

        # Gating Logic
        fast_score = self.risk_model.calculate_risk(report.findings)

        # If Critical -> Stop
        if any(f.severity == Severity.CRITICAL for f in fast_findings):
            log_ctx.info("Critical fast finding, aborting deep scan")
            custom_weights = effective_policy.custom_threat_weights if effective_policy else None
            report.risk_score = self.risk_model.calculate_risk(
                report.findings, custom_threat_weights=custom_weights
            )
            enrich_findings(report.findings)
            apply_evidence_contract(report.findings, report.file_type, report.file_path)
            self._apply_coverage(report)
            self._apply_unscannable_policy(report)
            report.verdict = self.risk_model.get_verdict(report.risk_score, report.findings)
            return report

        # T6 DOS HIGH → skip deep scan.  Confirmed-bomb documents can hang the
        # Docling parser even with subprocess isolation; the fast scan finding
        # is already sufficient to push the verdict to FLAG/BLOCK.
        if any(
            f.threat_id == ThreatID.T6_DOS and f.severity == Severity.HIGH
            for f in fast_findings
        ):
            log_ctx.info("T6 DOS HIGH finding in fast scan — skipping deep scan")
            custom_weights = effective_policy.custom_threat_weights if effective_policy else None
            report.risk_score = self.risk_model.calculate_risk(
                report.findings, custom_threat_weights=custom_weights
            )
            enrich_findings(report.findings)
            apply_evidence_contract(report.findings, report.file_type, report.file_path)
            self._apply_coverage(report)
            self._apply_unscannable_policy(report)
            report.verdict = self.risk_model.get_verdict(report.risk_score, report.findings)
            return report

        # Determine Deep Scan
        should_deep_scan = False
        if fast_score >= self.config.thresholds.deep_scan_trigger:
            should_deep_scan = True
        elif ftype == "unknown" and size_mb < self.config.limits.max_mb:
            should_deep_scan = True
        elif (
            (ftype == "pdf" and self.config.enable_pdf)
            or (ftype == "docx" and self.config.enable_docx)
            or (ftype == "pptx" and self.config.enable_pptx)
            or (ftype == "xlsx" and self.config.enable_xlsx)
            or (ftype == "rtf" and self.config.enable_rtf)
            or (ftype == "html" and self.config.enable_html)
            or (
                ftype.startswith("ole")
                and getattr(self.config, "enable_legacy_office", True)
            )
            or (ftype == "csv" and getattr(self.config, "enable_csv", True))
            or (
                ftype.startswith("odf.")
                and getattr(self.config, "enable_odf", True)
            )
        ):
            should_deep_scan = True

        if not should_deep_scan:
            log_ctx.info("Skipping deep scan (score below threshold)", score=fast_score)
            report.risk_score = fast_score
            enrich_findings(report.findings)
            apply_evidence_contract(report.findings, report.file_type, report.file_path)
            self._apply_coverage(report)
            self._apply_unscannable_policy(report)
            report.verdict = self.risk_model.get_verdict(report.risk_score, report.findings)
            return report

        # --- STAGE 2: DEEP SCAN ---
        parsed_doc: Optional[ParsedDocument] = None

        # 2a. Parsing
        with Timer() as t:
            try:

                def _parse_task():
                    if ftype == "pdf" and self.config.enable_pdf:
                        return parse_pdf(file_path, self.config)
                    elif ftype == "docx" and self.config.enable_docx:
                        return parse_docx(file_path, self.config)
                    elif ftype == "pptx" and self.config.enable_pptx:
                        return parse_pptx(file_path, self.config)
                    elif ftype == "xlsx" and self.config.enable_xlsx:
                        return parse_xlsx(file_path, self.config)
                    elif ftype == "rtf" and self.config.enable_rtf:
                        return parse_rtf(file_path, self.config)
                    elif ftype == "html" and self.config.enable_html:
                        return parse_html(file_path, self.config)
                    elif ftype.startswith("ole") and getattr(
                        self.config, "enable_legacy_office", True
                    ):
                        return parse_ole(file_path, self.config)
                    elif ftype == "csv" and getattr(
                        self.config, "enable_csv", True
                    ):
                        return parse_csv(file_path, self.config)
                    elif ftype.startswith("odf.") and getattr(
                        self.config, "enable_odf", True
                    ):
                        return parse_odf(file_path, self.config)
                    return ParsedDocument(
                        file_path=file_path, file_type=ftype, text="", metadata={}
                    )

                parsed_doc = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, _parse_task),
                    timeout=self.config.limits.parse_timeout_ms / 1000.0,
                )
            except asyncio.TimeoutError:
                log_ctx.error("Parsing timed out — scan incomplete")
                report.metadata.setdefault("timed_out_stages", []).append("parse")
                report.add(self._timeout_finding(
                    "parse", self.config.limits.parse_timeout_ms
                ))
            except Exception as e:
                log_ctx.error("Parsing failed", error=str(e))
                report.add(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.MEDIUM,
                        title="Parsing failed",
                        explain=f"Document parsing error: {type(e).__name__}",
                        module="stage.parse",
                    )
                )
        report.timings_ms["parse"] = t.duration_ms

        if parsed_doc:
            # 2b. Format Checks (Active Content / Obfuscation)
            with Timer() as t:
                try:

                    def _format_checks_task():
                        fs = []
                        if self.config.enable_active_content_checks:
                            if parsed_doc.file_type == "pdf":
                                fs.extend(
                                    detect_pdf_active_content(parsed_doc, self.config)
                                )
                            elif parsed_doc.file_type == "docx":
                                fs.extend(
                                    detect_docx_external_refs(parsed_doc, self.config)
                                )
                                fs.extend(
                                    detect_docx_ole_objects(parsed_doc, self.config)
                                )
                                fs.extend(detect_docx_macros(parsed_doc, self.config))
                            elif parsed_doc.file_type == "pptx":
                                fs.extend(
                                    detect_pptx_external_refs(parsed_doc, self.config)
                                )
                                fs.extend(detect_pptx_macros(parsed_doc, self.config))
                            elif parsed_doc.file_type == "xlsx":
                                fs.extend(
                                    detect_xlsx_external_refs(parsed_doc, self.config)
                                )
                                fs.extend(detect_xlsx_macros(parsed_doc, self.config))

                        if self.config.enable_obfuscation_checks:
                            if parsed_doc.file_type == "pdf":
                                fs.extend(
                                    detect_pdf_obfuscation(parsed_doc, self.config)
                                )
                            # Obfuscation logic for docx/pptx/xlsx handled in fast scan
                        return fs

                    format_findings = await asyncio.wait_for(
                        loop.run_in_executor(self._executor, _format_checks_task),
                        timeout=self.config.limits.format_checks_timeout_ms / 1000.0,
                    )
                    report.findings.extend(format_findings)
                except asyncio.TimeoutError:
                    log_ctx.error("Format checks timed out — scan incomplete")
                    report.metadata.setdefault("timed_out_stages", []).append(
                        "format_checks"
                    )
                    report.add(self._timeout_finding(
                        "format_checks",
                        self.config.limits.format_checks_timeout_ms,
                    ))
                except Exception as e:
                    log_ctx.error("Format checks failed", error=str(e))
            report.timings_ms["format_checks"] = t.duration_ms

            # 2c. Detectors
            with Timer() as t:
                _det_skipped: list[str] = []

                try:
                    def _detectors_task() -> list[Finding]:
                        out: list[Finding] = []
                        for det in self.detectors:
                            breaker = self._breakers.get(det.name)
                            if breaker is not None and breaker.state.value == "open":
                                _det_skipped.append(det.name)
                                log_ctx.warning(
                                    "Detector circuit open — skipping",
                                    detector=det.name,
                                    failures=breaker.failure_count,
                                )
                                continue
                            try:
                                findings = (
                                    breaker.call(det.run, parsed_doc, self.config)
                                    if breaker is not None
                                    else det.run(parsed_doc, self.config)
                                )
                                out.extend(findings)
                            except CircuitOpenError:
                                _det_skipped.append(det.name)
                            except Exception as exc:
                                log_ctx.warning(
                                    "Detector error",
                                    detector=det.name,
                                    error=str(exc),
                                )
                        return out

                    det_findings = await asyncio.wait_for(
                        loop.run_in_executor(self._executor, _detectors_task),
                        timeout=self.config.limits.detectors_timeout_ms / 1000.0,
                    )
                    report.findings.extend(det_findings)
                except asyncio.TimeoutError:
                    # A timeout of *our own* detector stage is an operational
                    # event (heavy ML over a large but benign document can
                    # exceed the budget), NOT evidence that the document is a
                    # DoS attack. But the scan is incomplete, so it must not
                    # silently ALLOW either (H.6, 0.4.8): emit the
                    # operational timeout finding, which escalates to FLAG
                    # (or BLOCK when on_timeout_verdict='block') while
                    # explicitly stating it is not a malice claim.
                    log_ctx.warning(
                        "Detector stage timed out — scan incomplete",
                        timeout_ms=self.config.limits.detectors_timeout_ms,
                    )
                    report.metadata["detectors_timed_out"] = True
                    report.metadata.setdefault("timed_out_stages", []).append(
                        "detectors"
                    )
                    report.add(self._timeout_finding(
                        "detectors", self.config.limits.detectors_timeout_ms
                    ))
                except Exception as e:
                    log_ctx.error("Detectors failed", error=str(e))

                if _det_skipped:
                    report.metadata["skipped_detectors"] = _det_skipped

            report.timings_ms["detectors"] = t.duration_ms

            # 2d. Antivirus (Optional)
            if self.config.antivirus_engine is not None:
                with Timer() as t:
                    try:

                        def _av_task():
                            return self.config.antivirus_engine.scan_file(file_path)

                        av_res = await asyncio.wait_for(
                            loop.run_in_executor(self._executor, _av_task),
                            timeout=self.config.limits.antivirus_timeout_ms / 1000.0,
                        )

                        if av_res.get("infected"):
                            report.add(
                                Finding(
                                    threat_id=ThreatID.T1_MALWARE,
                                    severity=Severity.CRITICAL,
                                    title="Antivirus detection",
                                    explain=(
                                        "Antivirus engine reported the "
                                        "file as infected."
                                    ),
                                    evidence=av_res,
                                    module="integrations.antivirus",
                                    # Third-party AV signature match — definitive.
                                    verdict_class=VerdictClass.BLOCK,
                                )
                            )
                    except asyncio.TimeoutError:
                        log_ctx.warning("AV scan timed out — scan incomplete")
                        report.metadata.setdefault("timed_out_stages", []).append(
                            "antivirus"
                        )
                        report.add(self._timeout_finding(
                            "antivirus", self.config.limits.antivirus_timeout_ms
                        ))
                    except Exception as e:
                        log_ctx.error("Antivirus failed", error=str(e))
                        report.add(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.LOW,
                                title="AV check failed",
                                explain=(
                                    f"Antivirus integration error: {type(e).__name__}"
                                ),
                                module="stage.antivirus",
                            )
                        )
                report.timings_ms["antivirus"] = t.duration_ms

            # Populate content preview
            report.content = {
                "text": (parsed_doc.text[:1000] + "...")
                if len(parsed_doc.text) > 1000
                else parsed_doc.text,
                "metadata": parsed_doc.metadata,
            }

        # Finalize
        custom_weights = effective_policy.custom_threat_weights if effective_policy else None
        report.risk_score = self.risk_model.calculate_risk(
            report.findings, custom_threat_weights=custom_weights
        )
        enrich_findings(report.findings)
        apply_evidence_contract(report.findings, report.file_type, report.file_path)
        self._apply_coverage(report)
        self._apply_unscannable_policy(report)
        report.verdict = self.risk_model.get_verdict(report.risk_score, report.findings)

        # Required-detector validation — record which required threat IDs had no findings
        if effective_policy and effective_policy.required_detectors:
            fired_threats = {f.threat_id.value for f in report.findings}
            # Normalise "T4" → "T4_PROMPT_INJECTION" style prefix matching
            missing = []
            for req in effective_policy.required_detectors:
                if not any(t == req or t.startswith(req + "_") for t in fired_threats):
                    missing.append(req)
            if missing:
                report.metadata["missing_required_detectors"] = missing
                log_ctx.warning("Required detectors produced no findings", missing=missing)

        log_ctx.info(
            "Scan complete", verdict=report.verdict.value, score=report.risk_score
        )

        # Append immutable audit entry if a log path is configured
        if self.config.audit_log_path:
            try:
                from .audit_log import AuditLog
                AuditLog(self.config.audit_log_path).write(report)
            except Exception as _audit_err:
                log_ctx.warning("Audit log write failed", error=str(_audit_err))

        return report

    def scan(self, file_path: str, policy_name: Optional[str] = None) -> ScanReport:
        """Synchronous wrapper (blocking). Uses asyncio.run() for safety."""
        try:
            asyncio.get_running_loop()
            is_running = True
        except RuntimeError:
            is_running = False

        if is_running:
            from concurrent.futures import ThreadPoolExecutor as _TPE

            with _TPE(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run, self.scan_async(file_path, policy_name=policy_name)
                )
                return future.result()
        else:
            return asyncio.run(self.scan_async(file_path, policy_name=policy_name))

    # Alias for backward compatibility with CLI and external callers
    scan_sync = scan


def scan(
    file_path: str,
    config: Optional[ScanConfig] = None,
    policy_name: Optional[str] = None,
    policy_engine: Optional[PolicyEngine] = None,
) -> ScanReport:
    return Scanner(config=config, policy_engine=policy_engine).scan(
        file_path, policy_name=policy_name
    )
