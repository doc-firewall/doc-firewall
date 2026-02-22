# Mock sentence_transformers before anything else imports it
import sys
import unittest
import os
from unittest.mock import MagicMock, patch

# Pre-inject mocks into sys.modules
mock_st = MagicMock()
sys.modules["sentence_transformers"] = mock_st
mock_torch = MagicMock()
sys.modules["torch"] = mock_torch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.config import ScanConfig
from doc_firewall.enums import Verdict, ThreatID, Severity
from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.detectors.yara import YaraDetector
from doc_firewall.detectors.hidden_text import HiddenTextDetector
from doc_firewall.detectors.pii import PiiDetector
from doc_firewall.detectors.secrets import SecretsDetector
from doc_firewall.detectors.prompt_injection import PromptInjectionDetector
from doc_firewall.detectors.metadata_injection import MetadataInjectionDetector
from doc_firewall.detectors.embedded_payload import EmbeddedPayloadDetector
from doc_firewall.detectors.dos_pdf import PdfDoSDetector
from doc_firewall.risk_model import RiskModel
from doc_firewall.report import Finding
from doc_firewall.scanner import Scanner

class TestRiskModel(unittest.TestCase):
    def test_risk_model_probabilistic(self):
        config = ScanConfig()
        model = RiskModel(config)
        
        # Two findings: T2 (0.9) * HIGH (0.8) and T4 (0.8) * HIGH (0.8)
        # Prob 1 = 0.9 * 0.8 * 1.0 = 0.72
        # Prob 2 = 0.8 * 0.8 * 1.0 = 0.64
        # Risk = 1 - (1-0.72)*(1-0.64) = 1 - (0.28 * 0.36) = 1 - 0.1008 = 0.8992
        
        findings = [
            Finding(ThreatID.T2_ACTIVE_CONTENT, Severity.HIGH, "F1", "E1", 
                    module="test"),
            Finding(ThreatID.T4_PROMPT_INJECTION, Severity.HIGH, "F2", "E2", 
                    module="test")
        ]
        
        score = model.calculate_risk(findings)
        self.assertAlmostEqual(score, 0.8992, places=4)
        c_verdict = model.get_verdict(score)
        # 0.8992 > 0.65 -> BLOCK
        self.assertEqual(c_verdict, Verdict.BLOCK)
        
    def test_risk_profiles(self):
        # Strict
        c_strict = ScanConfig(profile="strict")
        self.assertEqual(c_strict.thresholds.flag, 0.15)
        self.assertEqual(c_strict.thresholds.block, 0.50)
        
        # Lenient
        c_lenient = ScanConfig(profile="lenient")
        self.assertEqual(c_lenient.thresholds.flag, 0.35)
        self.assertEqual(c_lenient.thresholds.block, 0.80)

class TestAdditionalDetectors(unittest.TestCase):
    def test_metadata_injection_detector(self):
        det = MetadataInjectionDetector()
        cfg = ScanConfig()
        
        # HTML in comments
        doc = ParsedDocument(
            "test", "docx", "text", metadata={}, 
            docx={"comments": ["<script>alert(1)</script>"]}
        )
        findings = det.run(doc, cfg)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].threat_id, ThreatID.T8_METADATA_INJECTION)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_embedded_payload(self):
        det = EmbeddedPayloadDetector()
        cfg = ScanConfig()
        
        # Base64 > 1KB
        payload = "A"*1025
        doc = ParsedDocument("test", "txt", f"Text with {payload} inside")
        findings = det.run(doc, cfg)
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].threat_id, ThreatID.T7_EMBEDDED_PAYLOAD)

    @patch("builtins.open")
    def test_pdf_dos_fast(self, mock_open_func):
        # Mocking file read to return a mock object where we control len() and count()
        mock_file = MagicMock()
        mock_open_func.return_value.__enter__.return_value = mock_file
        
        mock_data = MagicMock()
        # Mocking read(limit_bytes)
        mock_file.read.return_value = mock_data
        
        # Simulate 100KB size
        mock_data.__len__.return_value = 102400 
        # Simulate 40000 objects (Density 400 > 300)
        mock_data.count.return_value = 40000
        
        findings = PdfDoSDetector.fast_scan("test.pdf", ScanConfig())
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].threat_id, ThreatID.T6_DOS)
        self.assertIn("High PDF Object Density", findings[0].title)

class TestV4Features(unittest.TestCase):
    
    def test_yara_detector_text(self):
        # We need to simulate yara being present in the module
        mock_yara = MagicMock()
        mock_rules = MagicMock()
        mock_yara.compile.return_value = mock_rules
        
        # Setup match
        match = MagicMock()
        match.rule = "TestRule"
        match.tags = ["test"]
        match.meta = {}
        mock_rules.match.return_value = [match]
        
        # Patch the yara variable in the detector module
        with patch("doc_firewall.detectors.yara.yara", mock_yara), \
             patch("os.path.exists", return_value=True):
            
            det = YaraDetector()
            cfg = ScanConfig(enable_yara=True, yara_rules_path="rules.yar")
            doc = ParsedDocument("test.bin", "bin", "suspicious text content")
            
            findings = det.run(doc, cfg)
            
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].threat_id, ThreatID.T1_MALWARE)
        self.assertIn("TestRule", findings[0].title)

    def test_hidden_text_detector(self):
        det = HiddenTextDetector()
        
        cfg = ScanConfig(enable_hidden_text=True)
        
        # Test case: docx with hidden text in metadata
        doc = ParsedDocument(
            "test.docx", "docx", "visible text", 
            docx={
                "hidden_text": "This is a secret payload hidden in the document structure."
            }
        )
        
        findings = det.run(doc, cfg)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].threat_id, ThreatID.T3_OBFUSCATION)
        self.assertIn("Hidden Text", findings[0].title)

    def test_pii_detector(self):
        det = PiiDetector()
        cfg = ScanConfig(enable_pii_checks=True)
        
        # Test case: text with Fake SSN
        text_with_pii = "My SSN is 123-45-6789 and email is test@example.com."
        doc = ParsedDocument("resume.pdf", "pdf", text_with_pii)
        
        findings = det.run(doc, cfg)
        self.assertTrue(len(findings) > 0)
        # Check that evidence contains SSN match
        evidence = findings[0].evidence["matches"]
        types = [m["type"] for m in evidence]
        self.assertIn("US SSN", types)
        self.assertIn("Email Address", types)

    def test_secrets_detector(self):
        det = SecretsDetector()
        cfg = ScanConfig(enable_secrets_checks=True)
        
        # Test case: AWS Key
        text_with_secret = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE"
        doc = ParsedDocument("config.txt", "txt", text_with_secret)
        
        # 
        findings = det.run(doc, cfg)
        self.assertTrue(len(findings) > 0)
        self.assertIn("AWS Access Key", findings[0].evidence["matches"][0]["type"])

    def test_prompt_injection_semantic(self):
        # Setup mocks properly
        # Because sys.modules patching is brittle with test discovery, we inject directly into the module
        import doc_firewall.detectors.prompt_injection as pi_module
        
        # Reset model
        pi_module.PromptInjectionDetector._model = None
        
        # Inject Mock SentenceTransformer and util into the module namespace
        mock_st_class = MagicMock()
        pi_module.SentenceTransformer = mock_st_class
        
        mock_util = MagicMock()
        pi_module.util = mock_util
        
        # Setup behavior
        mock_model_instance = mock_st_class.return_value
        mock_model_instance.encode.return_value = "tensor_mock"
        
        mock_scores = MagicMock()
        mock_scores.max.return_value = 0.95
        mock_scores.__float__ = lambda x: 0.95
        mock_scores.__gt__ = lambda x, y: 0.95 > y
        mock_util.cos_sim.return_value = [mock_scores]

        # Force flag
        with patch("doc_firewall.detectors.prompt_injection._HAS_TRANSFORMERS", True):
            det = PromptInjectionDetector()
            cfg = ScanConfig(enable_semantic_scans=True, enable_prompt_injection=True)
            doc = ParsedDocument("test.txt", "txt", "Low risk text by regex")
            
            # Run
            findings = det.run(doc, cfg)
            
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].threat_id, ThreatID.T4_PROMPT_INJECTION)

class TestAsyncScanner(unittest.IsolatedAsyncioTestCase):
    async def test_async_scan_flow(self):
        scanner = Scanner()
        # Mock detectors to avoid running real ones which caused test flakes
        scanner.detectors = []
        
        # Mock external dependencies called in executor
        with patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=100), \
             patch("doc_firewall.scanner.sha256_file", return_value="hash"), \
             patch("doc_firewall.scanner.guess_file_type", return_value="pdf"), \
             patch("doc_firewall.scanner.PdfDoSDetector.fast_scan", return_value=[]), \
             patch("doc_firewall.scanner.EmbeddedPayloadDetector.fast_scan", 
                   return_value=[]), \
             patch("doc_firewall.scanner.fast_scan_pdf", return_value=[]), \
             patch("doc_firewall.scanner.parse_pdf", return_value=ParsedDocument("test.pdf", "pdf", "content")), \
             patch("doc_firewall.scanner.detect_pdf_active_content", return_value=[]), \
             patch("doc_firewall.scanner.detect_pdf_obfuscation", return_value=[]):
            
            # Run scan
            report = await scanner.scan_async("test.pdf")
            
            self.assertIsNotNone(report)
            self.assertEqual(report.verdict, Verdict.ALLOW)
            self.assertIn("fast_scan", report.timings_ms)
            self.assertIn("parse", report.timings_ms)

if __name__ == "__main__":
    unittest.main()
