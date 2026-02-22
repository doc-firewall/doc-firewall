"""
Example 3: Processing JSON Results

This example demonstrates how to convert the scan report into a dictionary/JSON
format, which is useful for building APIs, logging, or sending results to a frontend.
"""

import sys
import os
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall import scan

def main():
    file_path = os.path.join(os.path.dirname(__file__), "samples/benign_0000.pdf")
    
    if not os.path.exists(file_path):
        file_path = "examples/samples/benign_0000.pdf"
        
    if not os.path.exists(file_path):
        file_path = "dummy_resume.pdf" # Mock file
        with open(file_path, "w") as f: f.write("Resume content...")

    print("Scanning...")
    report = scan(file_path)

    # Convert report object to a dictionary
    report_dict = report.to_dict()

    # Add extra metadata if needed (e.g., request ID, user ID)
    report_dict["scan_date"] = datetime.now().isoformat()
    report_dict["user_id"] = "user_123"

    # Print pretty JSON
    print("\n--- JSON Result ---")
    print(json.dumps(report_dict, indent=2, default=str))

    # Example: How an API might handle the response
    if report_dict["verdict"] == "BLOCK":
        response = {"status": "error", "message": "File upload rejected due to security policy."}
    else:
        response = {"status": "success", "file_id": "uploaded_123"}
    
    print("\n--- API Response ---")
    print(response)

    if file_path == "dummy_resume.pdf":
        os.remove(file_path)

if __name__ == "__main__":
    main()
