from __future__ import annotations
import os
import asyncio
import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from .config import ScanConfig
from .enums import ThreatID, Severity
from .report import ScanReport, Finding
from .risk_model import RiskModel
from .analyzers.pdf.fast_scan import fast_scan_pdf
from .analyzers.docx.fast_scan import fast_scan_docx
from .analyzers.pdf.parser import parse_pdf, ParsedDocument
from .analyzers.docx.parser import parse_docx

# format checks
from .analyzers.pdf.active_content import detect_pdf_active_content
from .analyzers.pdf.obfuscation import detect_pdf_obfuscation
from .analyzers.docx.external_refs import detect_docx_external_refs
from .analyzers.docx.ole import detect_docx_ole_objects
from .analyzers.docx.macros import detect_docx_macros
from .detectors.embedded_payload import EmbeddedPayloadDetector
from .detectors.dos_pdf import PdfDoSDetector
from .detectors.metadata_injection import MetadataInjectionDetector
from .detectors.ats_manipulation import ATSManipulationDetector
from .detectors.prompt_injection import PromptInjectionDetector
from .detectors.ranking_manipulation import RankingManipulationDetector
from .detectors.yara import YaraDetector

from .utils.hashing import sha256_file
from .utils.mime import guess_file_type
from .logger import get_logger

logger = get_logger()


_MAGIC_BYTES = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "docx",  # ZIP/DOCX
}


def _detect_file_type_by_magic(path: str) -> str:
    """Detect file type using magic bytes (first 8 bytes)."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        for magic, ftype in _MAGIC_BYTES.items():
            if header.startswith(magic):
                return ftype
    except OSError:
        pass
    return "unknown"


class Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.end = time.perf_counter()
        self.duration_ms = (self.end - self.start) * 1000.0


class Scanner:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.risk_model = RiskModel(self.config)
        self._executor = ThreadPoolExecutor(
            max_workers=getattr(self.config, "max_workers", 4)
        )
        # Initialize detectors
        self.detectors = [
            EmbeddedPayloadDetector(),
            PdfDoSDetector(),  # Deep scan for DoS
            MetadataInjectionDetector(),
            ATSManipulationDetector(),
            PromptInjectionDetector(),
            RankingManipulationDetector(),
            YaraDetector(),
        ]

    async def scan_async(self, file_path: str) -> ScanReport:
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

        log_ctx = logger.bind(file_path=file_path, sha256=sha, file_type=ftype)
        log_ctx.info("Starting scan")

        report = ScanReport(
            file_path=file_path, file_type=ftype, sha256=sha, size_bytes=size_bytes
        )

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
            report.verdict = self.risk_model.get_verdict(report.risk_score)
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
                elif (
                    "word" in ftype or "docx" in ftype or "zip" in ftype
                ) and self.config.enable_docx:
                    findings.extend(fast_scan_docx(file_path, self.config))

                # 3. New DoS Fast Checks
                if "pdf" in ftype and self.config.enable_pdf:
                    findings.extend(PdfDoSDetector.fast_scan(file_path, self.config))

                return findings

            try:
                fast_findings = await loop.run_in_executor(
                    self._executor, _run_fast_scan
                )
            except Exception as e:
                log_ctx.error("Fast scan error", error=str(e))

        report.timings_ms["fast_scan"] = t.duration_ms
        report.findings.extend(fast_findings)

        # Gating Logic
        fast_score = self.risk_model.calculate_risk(report.findings)

        # If Critical -> Stop
        if any(f.severity == Severity.CRITICAL for f in fast_findings):
            log_ctx.info("Critical fast finding, aborting deep scan")
            report.risk_score = fast_score
            report.verdict = self.risk_model.get_verdict(report.risk_score)
            return report

        # Determine Deep Scan
        should_deep_scan = False
        if fast_score >= self.config.thresholds.deep_scan_trigger:
            should_deep_scan = True
        elif ftype == "unknown" and size_mb < self.config.limits.max_mb:
            should_deep_scan = True
        elif (ftype == "pdf" and self.config.enable_pdf) or (
            ftype == "docx" and self.config.enable_docx
        ):
            should_deep_scan = True

        if not should_deep_scan:
            log_ctx.info("Skipping deep scan (score below threshold)", score=fast_score)
            report.risk_score = fast_score
            report.verdict = self.risk_model.get_verdict(report.risk_score)
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
                    return ParsedDocument(
                        file_path=file_path, file_type=ftype, text="", metadata={}
                    )

                parsed_doc = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, _parse_task),
                    timeout=self.config.limits.parse_timeout_ms / 1000.0,
                )
            except asyncio.TimeoutError:
                log_ctx.error("Parsing timed out")
                report.add(
                    Finding(
                        threat_id=ThreatID.T6_DOS,
                        severity=Severity.HIGH,
                        title="Parsing timed out",
                        explain="Document parsing exceeded time limit.",
                        module="stage.parse",
                    )
                )
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

                        if self.config.enable_obfuscation_checks:
                            if parsed_doc.file_type == "pdf":
                                fs.extend(
                                    detect_pdf_obfuscation(parsed_doc, self.config)
                                )
                            # Docx obfuscation logic usually in fast scan or active
                            # content for now
                        return fs

                    format_findings = await asyncio.wait_for(
                        loop.run_in_executor(self._executor, _format_checks_task),
                        timeout=self.config.limits.format_checks_timeout_ms / 1000.0,
                    )
                    report.findings.extend(format_findings)
                except asyncio.TimeoutError:
                    report.add(
                        Finding(
                            threat_id=ThreatID.T6_DOS,
                            severity=Severity.MEDIUM,
                            title="Format checks timed out",
                            explain="Static analysis checks exceeded time limit.",
                            module="stage.format_checks",
                        )
                    )
                except Exception as e:
                    log_ctx.error("Format checks failed", error=str(e))
            report.timings_ms["format_checks"] = t.duration_ms

            # 2c. Detectors
            with Timer() as t:
                try:

                    def _detectors_task():
                        out = []
                        for det in self.detectors:
                            out.extend(det.run(parsed_doc, self.config))
                        return out

                    det_findings = await asyncio.wait_for(
                        loop.run_in_executor(self._executor, _detectors_task),
                        timeout=self.config.limits.detectors_timeout_ms / 1000.0,
                    )
                    report.findings.extend(det_findings)
                except asyncio.TimeoutError:
                    report.add(
                        Finding(
                            threat_id=ThreatID.T6_DOS,
                            severity=Severity.MEDIUM,
                            title="Detectors timed out",
                            explain="Detection models exceeded time limit.",
                            module="stage.detectors",
                        )
                    )
                except Exception as e:
                    log_ctx.error("Detectors failed", error=str(e))
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
                                )
                            )
                    except asyncio.TimeoutError:
                        report.add(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.MEDIUM,
                                title="AV scan timed out",
                                explain="Antivirus engine exceeded time limit.",
                                module="stage.antivirus",
                            )
                        )
                    except Exception as e:
                        log_ctx.error("Antivirus failed", error=str(e))
                        report.add(
                            Finding(
                                threat_id=ThreatID.T6_DOS,
                                severity=Severity.LOW,
                                title="AV check failed",
                                explain=(
                                    "Antivirus integration error: "
                                    f"{type(e).__name__}"
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
        report.risk_score = self.risk_model.calculate_risk(report.findings)
        report.verdict = self.risk_model.get_verdict(report.risk_score)
        log_ctx.info(
            "Scan complete", verdict=report.verdict.value, score=report.risk_score
        )
        return report

    def scan(self, file_path: str) -> ScanReport:
        """Synchronous wrapper (blocking). Uses asyncio.run() for safety."""
        try:
            asyncio.get_running_loop()
            is_running = True
        except RuntimeError:
            is_running = False

        if is_running:
            # Already inside an async context — run in a separate thread
            # to avoid reentrancy bugs from nest_asyncio
            from concurrent.futures import ThreadPoolExecutor as _TPE

            with _TPE(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.scan_async(file_path))
                return future.result()
        else:
            return asyncio.run(self.scan_async(file_path))


def scan(file_path: str, config: Optional[ScanConfig] = None) -> ScanReport:
    return Scanner(config=config).scan(file_path)
