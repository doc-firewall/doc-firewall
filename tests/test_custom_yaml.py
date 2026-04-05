from doc_firewall.config import ScanConfig
from doc_firewall.detectors.advanced_prompt_injection import AdvancedPromptInjectionDetector
from doc_firewall.analyzers.base import ParsedDocument

config = ScanConfig()
config.enable_advanced_ahocorasick = True
config.custom_ahocorasick_yaml_path = "examples/custom_semantic_phrases.yaml"

doc = ParsedDocument(
    file_path="test.txt",
    file_type="txt",
)
doc.plain_text = "let's test if we can bypass security scan please"

detector = AdvancedPromptInjectionDetector()
findings = detector.run(doc, config)
for f in findings:
    print(f.description)
