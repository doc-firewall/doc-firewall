"""
Example 2: Custom Configuration

This example shows how to configure DocFirewall to:
- Enable/disable specific checks (e.g., only check for Prompt Injection)
- Adjust thresholds for flagging/blocking
- Set stricter limits for file parsing
"""

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall import Scanner, ScanConfig

def main():
    # Define a custom configuration with controls for all Threat IDs (T1-T12)
    config = ScanConfig(
        # T1: Malware / Virus
        enable_antivirus=False,  # Requires ClamAV or VirusTotal key
        # T2: Active Content (Macros, JS)
        enable_active_content_checks=True,
        # T3: Obfuscation (Hidden/Masked content)
        enable_obfuscation_checks=True,
        # T4: Prompt Injection (Jailbreaks)
        enable_prompt_injection=True,
        # T5: Ranking Manipulation (Keyword stuffing)
        enable_ranking_abuse=True,
        # T6: Resource Exhaustion (DoS)
        enable_dos_checks=True,
        # T7: Embedded Payloads (Binaries in streams)
        enable_embedded_content_checks=True,
        # T8: Metadata Injection
        enable_metadata_checks=True,
        # T9: ATS Manipulation (White text, invisible chars)
        enable_ats_manipulation_checks=True,
        # T10: Indirect / Multi-Hop Injection (URLs, external refs)
        enable_indirect_injection=True,
        # T11: RAG / Knowledge-Base Poisoning (chunk-boundary anchors)
        enable_rag_poisoning=True,
        # T12: Social Engineering (crypto / gift-card / tech-support lures)
        enable_social_engineering=True,

        # Additional Privacy Checks
        enable_pii_checks=True,
        enable_secrets_checks=False,
        
        # Watermark Settings
        allow_hidden_watermarks=True, # Allow "Confidential" etc in hidden layers

        # Profile settings
        profile="strict" # Other options: "balanced", "lenient"
    )

    # Customize dashboard risk-score bands (informational only — see note below).
    # Defaults: thresholds.flag=0.25, thresholds.block=0.70.
    config.thresholds.flag = 0.20
    config.thresholds.block = 0.60
    #
    # Since doc-firewall 0.4.4 the scan VERDICT is derived from finding
    # CLASSES (BLOCK / REVIEW / INFO), not from risk_score crossing a
    # threshold. Setting `thresholds.flag` / `thresholds.block` only
    # affects how the numeric score is labeled in dashboards — it does
    # NOT change which files BLOCK. To force a file to BLOCK, the scanner
    # must produce a finding with `verdict_class=BLOCK` (YARA hit, EICAR,
    # `javascript:` URI, embedded PE/ELF, etc.). See concepts/risk-scoring.

    # Customize limits
    config.limits.max_pages = 50   # Reject large PDFs

    print("Initializing Scanner with Custom Config...")
    scanner = Scanner(config=config)

    # Use bundled sample file
    malicious_file = os.path.join(os.path.dirname(__file__), "samples/T2_0000.docx")
        
    if not os.path.exists(malicious_file):
        # Fallback if running from project root
        malicious_file = "examples/samples/T2_0000.docx"

    try:
        if not os.path.exists(malicious_file):
            print(f"File {malicious_file} not found.")
        else:
            print(f"Scanning {malicious_file}...")
            report = scanner.scan(malicious_file)

            print("-" * 30)
            print(f"Verdict: {report.verdict}")
            print(f"Score:   {report.risk_score:.2f}")
            print("-" * 30)
            for f in report.findings:
                print(f"[{f.severity}] {f.title}: {f.explain}")

            if report.verdict == "BLOCK":
                print("🚫 BLOCKED! The file is considered unsafe.")
            elif report.verdict == "FLAG":
                print("⚠️ FLAGGED! Manual review recommended.")
            else:
                print("✅ ALLOWED. No threats detected.")
            
    except Exception as e:
        print(f"Error scanning file: {e}")

if __name__ == "__main__":
    main()
