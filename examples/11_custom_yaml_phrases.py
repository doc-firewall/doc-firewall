from doc_firewall import Scanner, ScanConfig

# Configure scanner with a custom YAML file containing zero-day phrases
config = ScanConfig(
    enable_advanced_ahocorasick=True,
    custom_ahocorasick_yaml_path="examples/custom_semantic_phrases.yaml"
)

scanner = Scanner(config=config)

# Scan a file (for demonstration, we use a sample docx)
file_path = "examples/samples/T4_0000.pdf"
print(f"Scanning {file_path} with custom zero-day phrases...")
report = scanner.scan(file_path)

print("-" * 30)
print(f"Verdict:    {report.verdict}")
print(f"Risk Score: {report.risk_score:.2f}")
for f in report.findings:
    if "T4" in f.rule_id:
        print(f"[{f.severity}] {f.title}: {f.explain[:100]}...")
