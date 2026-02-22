"""
Example 1: Basic File Scan

This example demonstrates the simplest usage of DocFirewall: scanning a single file 
with default settings.
"""

import sys
import os

# Ensure we can import doc_firewall from src if running from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall import scan

def main():
    # Path to a file you want to scan
    # For this example, we use a sample DOCX file with active content (T2)
    
    # Check local samples first
    file_path = os.path.join(os.path.dirname(__file__), "samples/T2_0000.docx")
    if not os.path.exists(file_path):
        # Fallback to project root path
        file_path = "examples/samples/T2_0000.docx"


    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
    else:
        print(f"Scanning {file_path}...")
        
        # Run the scan
        report = scan(file_path)

        # Print results
        print("-" * 30)
        print(f"Verdict:    {report.verdict}")
        print(f"Risk Score: {report.risk_score:.2f}")
        print(f"Findings:   {len(report.findings)}")
        print("-" * 30)

        for f in report.findings:
            print(f"[{f.severity}] {f.title}: {f.explain}")

if __name__ == "__main__":
    main()
