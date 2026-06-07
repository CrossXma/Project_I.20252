import json
import os
from engine import MalwareDetector

# Paths to feature files
pe_benign_path = r"d:\Documents\Project 1\Project_I.20252\output\benign_pe_features.json"
pe_malware_path = r"d:\Documents\Project 1\Project_I.20252\output\malware_pe_features.json"
asm_benign_path = r"d:\Documents\Project 1\Project_I.20252\output\benign_asm_features.json"
asm_malware_path = r"d:\Documents\Project 1\Project_I.20252\output\malware_asm_features.json"

def load_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Feature file not found at {path}")
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def combine_features(pe_data, asm_data):
    combined = {}
    for h in pe_data:
        if h in asm_data:
            combined[h] = {
                "pe": pe_data[h],
                "asm": asm_data[h]
            }
    return combined

def main():
    # Load features
    pe_benign = load_json(pe_benign_path)
    pe_malware = load_json(pe_malware_path)
    asm_benign = load_json(asm_benign_path)
    asm_malware = load_json(asm_malware_path)

    benign_dataset = combine_features(pe_benign, asm_benign)
    malware_dataset = combine_features(pe_malware, asm_malware)

    detector = MalwareDetector()

    tp, fp, tn, fn = 0, 0, 0, 0
    false_positives = []
    false_negatives = []

    # Evaluate Malware
    for h, data in malware_dataset.items():
        res = detector.detect(data["pe"], data["asm"])
        if res["is_malware"]:
            tp += 1
        else:
            fn += 1
            false_negatives.append((h, data["pe"]["file_info"]["file_name"], res["score"], res["details"], res["detected_behaviors"]))

    # Evaluate Benign
    for h, data in benign_dataset.items():
        res = detector.detect(data["pe"], data["asm"])
        if res["is_malware"]:
            fp += 1
            false_positives.append((h, data["pe"]["file_info"]["file_name"], res["score"], res["details"], res["detected_behaviors"]))
        else:
            tn += 1

    # Metrics
    total = len(benign_dataset) + len(malware_dataset)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Output results
    print("==================================================")
    print("          MALWARE DETECTOR EVALUATION REPORT      ")
    print("==================================================")
    print(f"Total Evaluated Samples: {total}")
    print(f"  Benign Samples       : {len(benign_dataset)}")
    print(f"  Malware Samples      : {len(malware_dataset)}")
    print("--------------------------------------------------")
    print(f"True Positives (TP)    : {tp}")
    print(f"False Negatives (FN)   : {fn}")
    print(f"True Negatives (TN)    : {tn}")
    print(f"False Positives (FP)   : {fp}")
    print("--------------------------------------------------")
    print(f"Accuracy               : {accuracy:.4f}")
    print(f"Precision              : {precision:.4f}")
    print(f"Recall                 : {recall:.4f}")
    print(f"F1 Score               : {f1:.4f}")
    print("==================================================")

    if false_positives:
        print("\nFalse Positives Details:")
        for h, name, score, details, behaviors in false_positives:
            print(f"  Hash: {h} | Name: {name} | Score: {score}")
            print(f"    Details: {details}")
            print(f"    Behaviors: {behaviors}")

    if false_negatives:
        print("\nFalse Negatives Details:")
        for h, name, score, details, behaviors in false_negatives:
            print(f"  Hash: {h} | Name: {name} | Score: {score}")
            print(f"    Details: {details}")
            print(f"    Behaviors: {behaviors}")

if __name__ == "__main__":
    main()
