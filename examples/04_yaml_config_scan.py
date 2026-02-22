"""
Example 4: YAML Configuration Scan

This example demonstrates how to load scan configuration from a YAML file
instead of configuring it programmatically in Python. This is useful for 
deployment scenarios where configuration should be separate from code.
"""

import os
import sys

# Ensure we can import doc_firewall from src if running from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import argparse
from doc_firewall import Scanner, ScanConfig

def main():
    parser = argparse.ArgumentParser(description="Scan file using YAML config")
    parser.add_argument("file", help="Path to file to scan")
    parser.add_argument("--config", default="doc_firewall_config.yaml", help="Path to configuration file")
    args = parser.parse_args()

    # Load configuration
    try:
        config = ScanConfig.from_yaml(args.config)
        print(f"Loaded configuration from {args.config}")
    except FileNotFoundError:
        print(f"Config file not found: {args.config}. Using defaults.")
        config = ScanConfig()
    
    # Initialize scanner (Antivirus will be auto-initialized based on config)
    scanner = Scanner(config=config)
    
    # Run Scan
    print(f"Scanning {args.file}...")
    try:
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
            
        report = scanner.scan(args.file)
        
        print("\n--- Scan Report ---")
        print(f"File: {report.file_path}")
        print(f"Verdict: {report.verdict.value}")
        print(f"Risk Score: {report.risk_score}")
        
        if report.findings:
            print(f"\nFindings ({len(report.findings)}):")
            for f in report.findings:
                print(f" - [{f.severity.name}] {f.title}: {f.explain or ''}")
        else:
            print("\nNo threats detected.")
            
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
