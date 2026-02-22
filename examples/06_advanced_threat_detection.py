"""
Example 6: Advanced Threat Detection (All Vectors)

This example demonstrates DocFirewall's capabilities across multiple threat categories,
running scans against real adversarial samples from the dataset.

Threats Covered:
1. T4: Prompt Injection (Jailbreaking, Instruction Override)
2. T9: ATS Manipulation (Keyword Stuffing, Hidden Text)
3. T2: Active Content (JavaScript, Macros)
"""

import os
import sys

# Ensure we can import doc_firewall from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall import Scanner, ScanConfig
from doc_firewall.enums import Verdict, Severity, ThreatID

def scan_dataset_file(file_rel_path, label, config_overrides=None):
    # Use local samples from examples/samples
    sample_name = os.path.basename(file_rel_path)
    dataset_path = os.path.join(os.path.dirname(__file__), "samples", sample_name)
    
    if not os.path.exists(dataset_path):
        # Fallback for running from project root
        dataset_path = f"examples/samples/{sample_name}"
    
    if not os.path.exists(dataset_path):
        print(f"Skipping {label}: File not found at {dataset_path}")
        return

    print(f"\n--- Scanning: {label} ---")
    print(f"File: {os.path.basename(dataset_path)}")
        
    try:
        # Default config: Balanced profile
        # Some detectors require specific flags enabled
        config_kwargs = {
            "profile": "balanced",
            "enable_pdf": True,
            "enable_docx": True,
            "enable_antivirus": False, # Focus on structural logic
            "enable_ats_manipulation_checks": True,
            "enable_embedded_content_checks": True,
            "enable_hidden_text": True
        }
        
        # Apply overrides if any
        if config_overrides:
            config_kwargs.update(config_overrides)
            
        config = ScanConfig(**config_kwargs)
        scanner = Scanner(config=config)
        
        report = scanner.scan(dataset_path)
        
        print(f"Verdict: {report.verdict.name}")
        print(f"Risk Score: {report.risk_score}")
        
        if report.findings:
            print(f"✅ DETECTED {len(report.findings)} Threat Indicators:")
            for f in report.findings:
                print(f"  - [{f.threat_id.name}] {f.title}")
                print(f"    Explain: {f.explain}")
                if f.evidence:
                    # Print snippet if available, else raw evidence
                    if "snippet" in f.evidence:
                         print(f"    Snippet: {f.evidence['snippet'][:100]}...")
                    elif "matches" in f.evidence:
                         print(f"    Matches: {f.evidence['matches']}")
                    else:
                         print(f"    Evidence: {f.evidence}")
        else:
            print("❌ FAILED: No threats detected.")
            
    except Exception as e:
        print(f"Scan failed: {e}")

def main():
    print("=== DocFirewall Advanced Threat Examples ===\n")

    # --- Section 1: LLM Prompt Injection ---
    print(">>> 1. Prompt Injection & Jailbreaking")
    # T4_0000.pdf contains instructions to override the system prompt
    scan_dataset_file(
        "samples/T4_0000.pdf", 
        "T4 Prompt Injection (PDF)",
        config_overrides={"profile": "aggressive"} # Often requires stricter checks
    )
    
    # --- Section 2: ATS Manipulation ---
    print("\n>>> 2. ATS Manipulation (Obfuscation)")
    # T9_stuff_0000.docx contains repeated keywords hidden from view
    scan_dataset_file(
        "samples/T9_stuff_0000.docx", 
        "T9 Keyword Stuffing (DOCX)"
    )
    
    # T9_hidden_0000.docx contains text with white-on-white formatting or hidden attributes
    scan_dataset_file(
        "samples/T9_hidden_0000.docx", 
        "T9 Hidden Text (DOCX)"
    )

    # --- Section 3: Active Content ---
    print("\n>>> 3. Active Content (Malware Vectors)")
    # T2_0000.pdf contains embedded JavaScript actions (OpenAction)
    scan_dataset_file(
        "samples/T2_0000.pdf", 
        "T2 Javascript Injection (PDF)"
    )

    # T2_vba_0000.docx contains specific VBA macro structures (vbaProject.bin)
    scan_dataset_file(
        "samples/T2_vba_0000.docx", 
        "T2 VBA Macros (DOCX)"
    )

if __name__ == "__main__":
    main()
