"""
Example 5: Custom Antivirus Integration

This example demonstrates how to integrate external antivirus engines into DocFirewall.
Supported providers include:
- ClamAV (via clamd daemon)
- VirusTotal (via API)
- Generic CLI (invoke any shell command)

Installation Instructions for ClamAV:
- MacOS (Homebrew):
    brew install clamav
    # Edit /usr/local/etc/clamav/clamd.conf to set "TCPSocket 3310"
    # Start service:
    clamd
- Ubuntu/Debian:
    sudo apt-get install clamav-daemon
    sudo systemctl start clamav-daemon
- Docker (for x86_64):
    docker run -d -p 3310:3310 clamav/clamav
- Docker (for Apple Silicon / ARM64):
    docker run -d -p 3310:3310 --platform linux/amd64 clamav/clamav
    # OR use a community image like:
    docker run -d -p 3310:3310 mailu/clamav
"""

import os
import sys
# Ensure we can import doc_firewall from src if running from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall import Scanner, ScanConfig

def main():
    print("--- DocFirewall Custom Antivirus Example ---\n")

    # Path to check
    # Create a dummy EICAR test file for demonstration
    test_file = "eicar_test_sample.txt"
    with open(test_file, "w") as f:
        f.write(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    print(f"Created test file: {test_file}")


    # --- Scenario 1: Using ClamAV (clamd) ---
    print("\n[Scenario 1] ClamAV Configuration (clamd)")
    # This assumes 'clamd' is running on localhost:3310 (default)
    # If not running, the initialization or scan might log an error but won't crash 
    # unless you configure it to be strict.
    config_clam = ScanConfig(enable_antivirus=True)
    config_clam.antivirus.provider = "clamav"
    config_clam.antivirus.clamav_host = "localhost"
    config_clam.antivirus.clamav_port = 3310
    config_clam.antivirus.clamav_socket_path = None # Force TCP mode
    
    try:
        scanner_clam = Scanner(config=config_clam)
        print("ClamAV Scanner Initialized. Attempting scan...")
        # Note: ClamAV running in docker might not see files on host unless volumes mapped.
        # But if using TCP mode, we send file bytes over socket, so mapping isn't required!
        # DocFirewall's clamd client sends bytes.
        
        # To actually test this, you need clamd running. 
        # We will wrap in try/except so this example runs even if you don't have clamd.
        report_clam = scanner_clam.scan(test_file)
        print(f"ClamAV Verdict: {report_clam.verdict.value}")
        print(f"Risk Score: {report_clam.risk_score}")
        if report_clam.findings:
            print("Findings:")
            for finding in report_clam.findings:
                print(f"  - [{finding.severity.name}] {finding.title}: {finding.explain}")
                if finding.evidence:
                    print(f"    Evidence: {finding.evidence}")
        print(f"Scan Duration: {report_clam.timings_ms} ms")
        
    except Exception as e:
        print(f"ClamAV check skipped/failed (ensure clamd is running on port 3310): {e}")


    # --- Scenario 2: Using VirusTotal (Requires API Key) ---
    print("\n[Scenario 2] VirusTotal Configuration")
    vt_key = os.environ.get("VT_API_KEY")
    if vt_key:
        config_vt = ScanConfig(enable_antivirus=True)
        config_vt.antivirus.provider = "virustotal"
        config_vt.antivirus.virustotal_api_key = vt_key
        
        scanner = Scanner(config=config_vt)
        # report = scanner.scan(test_file)
        # ... logic to print report ...
        print("Scannery initialized with VirusTotal (Skipping actual scan to save API quota/time)")
    else:
        print("Skipping VirusTotal setup (VT_API_KEY env var not set)")


    # --- Scenario 3: Using Generic CLI (Simulating a scanner) ---
    print("\n[Scenario 3] Generic CLI (Simulation)")
    
    # We will simulate an antivirus using 'grep'. 
    # If it finds "EICAR", grep returns exit code 0.
    # We usually expect 0=Clean, 1=Infected in standard tools, but let's say our tool returns 0 if found.
    # Actually, commonly CLI tools return 0 for success/clean, and 1 for finding.
    # Let's use a python one-liner as our "antivirus binary" to be cross-platform compatible for this example.
    
    config_cli = ScanConfig(enable_antivirus=True)
    config_cli.antivirus.provider = "generic_cli"
    
    # Command: python -c "..."
    # If content contains EICAR -> exit 1 (Infected)
    # Else -> exit 0 (Clean)
    simulated_av_cmd = (
        sys.executable + 
        ' -c "import sys; '
        'content=open(\'{path}\').read(); '
        'sys.exit(1 if \'EICAR\' in content else 0)"'
    )
    
    config_cli.antivirus.generic_cli_command = simulated_av_cmd
    config_cli.antivirus.generic_cli_infected_codes = [1]
    
    scanner_cli = Scanner(config=config_cli)
    print(f"configured Generic CLI command: {simulated_av_cmd}")
    
    print(f"Scanning {test_file}...")
    report = scanner_cli.scan(test_file)
    
    print(f"Verdict: {report.verdict.value}")
    
    # Check if we caught it
    av_findings = [f for f in report.findings if f.threat_id.name == "T1_MALWARE"]
    if av_findings:
        print("✅ SUCCESS: The generic CLI integration detected the malware!")
        print(f"Finding Details: {av_findings[0].explain}")
        print(f"Metadata: {av_findings[0].evidence}")
    else:
        print("❌ FAILURE: Malware not detected.")

    # Cleanup
    os.remove(test_file)

if __name__ == "__main__":
    main()
