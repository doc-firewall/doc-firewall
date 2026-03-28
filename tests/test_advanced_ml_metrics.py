import sys
import os
import csv
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from doc_firewall import Scanner, ScanConfig

def main():
    # Only ML scanners
    config = ScanConfig(
        enable_active_content_checks=False,
        enable_obfuscation_checks=False,
        enable_prompt_injection=False,
        enable_ranking_abuse=False,
        enable_dos_checks=False,
        enable_embedded_content_checks=False,
        enable_metadata_checks=False,
        enable_ats_manipulation_checks=False,
        enable_secrets_checks=False,

        enable_advanced_ahocorasick=True,
        enable_advanced_bert=True,
        enable_advanced_tfidf=True,
        enable_credential_entropy=True,
    )

    print("Initializing Scanner with Advanced ML Config...")
    scanner = Scanner(config=config)

    dataset_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../dataset"))
    manifest_path = os.path.join(dataset_dir, "manifest.csv")

    if not os.path.exists(manifest_path):
        print(f"Manifest not found at {manifest_path}")
        return

    TP, FP, TN, FN = 0, 0, 0, 0
    scanned = 0

    print("Starting scan over dataset...")
    # Suppress verbose logging from libraries if needed
    logging.getLogger().setLevel(logging.ERROR)

    with open(manifest_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            relative_path = row['path']
            # manifest path sometimes includes 'dataset/' prefix
            if relative_path.startswith("dataset/"):
                relative_path = relative_path[len("dataset/"):]
            
            file_path = os.path.join(dataset_dir, relative_path)
            
            if not os.path.exists(file_path):
                continue

            is_malicious_expected = int(row['is_malicious'])
            threat_id = row.get("threat_ids", "")

            # Restrict ML test to relevant NLP threat vectors (T4, T5, T9) and benign files
            if is_malicious_expected == 1 and not any(t in threat_id for t in ["T4", "T5", "T9"]):
                continue
            
            try:
                report = scanner.scan(file_path)
                verdict = report.verdict == "BLOCK"

                if is_malicious_expected == 1:
                    if verdict:
                        TP += 1
                    else:
                        FN += 1
                else:
                    if verdict:
                        FP += 1
                    else:
                        TN += 1
                scanned += 1
                
                # Optional visual progress indicator
                if scanned % 100 == 0:
                    print(f"Scanned {scanned} files... (TP:{TP} FP:{FP} TN:{TN} FN:{FN})")

                # Print FN debugging logic
                if is_malicious_expected == 1 and not verdict:
                    threat_id = row.get("threat_ids", "UNKNOWN")
                    # print(f"FN Detected | Path: {file_path} | Threat: {threat_id}")

            except Exception as e:
                # Handle files that might fail to parse during deep scan
                print(f"Error scanning {file_path}: {e}")

    print(f"\n--- Metrics for Advanced ML Scanners ---")
    print(f"Total Scanned Files : {scanned}")
    print(f"True Positives (TP) : {TP}")
    print(f"False Positives (FP): {FP}")
    print(f"True Negatives (TN) : {TN}")
    print(f"False Negatives (FN): {FN}")
    
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (TP + TN) / scanned if scanned > 0 else 0
    
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"----------------------------------------\n")

if __name__ == "__main__":
    main()
