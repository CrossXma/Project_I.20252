import os
import json
import joblib

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# ==================================================
# CONFIG
# ==================================================

SUSPICIOUS_APIS = [
    "CreateProcessW",
    "VirtualAlloc",
    "VirtualFree",
    "WriteFile",
    "ReadFile",
    "CreateFileW",
    "LoadLibraryA",
    "GetProcAddress",
    "CreateThread",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "TerminateProcess",
    "WinExec",
    "ShellExecuteW",
    "ShellExecuteExW",
    "InternetOpen",
    "InternetConnect",
    "URLDownloadToFile",
    "RegOpenKeyExW",
    "RegSetValueExW",
    "SetWindowsHookExW"
]


COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3389
]

BENIGN_PE_PATH = "./output/benign_pe_features.json"
BENIGN_ASM_PATH = "./output/benign_asm_features.json"
MALWARE_PE_PATH = "./output/malware_pe_features.json"
MALWARE_ASM_PATH = "./output/malware_asm_features.json"
OUTPUT_DIR = "./output/dataset"

# ==================================================
# UTILITIES
# ==================================================

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_section_entropy_features(sections):

    entropies = []

    for sec in sections:
        entropy = sec.get("entropy")

        if entropy is not None:
            entropies.append(entropy)

    if len(entropies) == 0:

        return {
            "avg_entropy": 0,
            "max_entropy": 0,
            "min_entropy": 0
        }

    return {
        "avg_entropy": sum(entropies) / len(entropies),
        "max_entropy": max(entropies),
        "min_entropy": min(entropies)
    }


def extract_import_features(imports):

    features = {}

    features["num_imported_dlls"] = len(imports)

    features["num_imported_apis"] = sum(
        len(api_list)
        for api_list in imports.values()
    )

    all_imports = set()

    for api_list in imports.values():
        all_imports.update(api_list)

    for api in SUSPICIOUS_APIS:
        features[f"api_{api}"] = int(
            api in all_imports
        )

    return features


def extract_opcode_features(top_opcodes):

    features = {}

    for opcode, count in top_opcodes.items():
        features[f"opcode_{opcode}"] = count

    return features


def extract_port_features(detected_ports):

    features = {}

    port_set = set(detected_ports)

    for port in COMMON_PORTS:

        features[f"port_{port}"] = int(
            port in port_set
        )

    return features


# ==================================================
# FEATURE EXTRACTION
# ==================================================

def build_sample_features(pe_sample, asm_sample):

    row = {}

    # ------------------------------------------
    # FILE INFO
    # ------------------------------------------

    file_info = pe_sample.get(
        "file_info",
        {}
    )

    row["file_size"] = file_info.get(
        "file_size_bytes",
        0
    )

    # ------------------------------------------
    # HEADERS
    # ------------------------------------------

    headers = pe_sample.get(
        "headers",
        {}
    )

    row["num_sections"] = headers.get(
        "number_of_sections",
        0
    )

    # ------------------------------------------
    # SECTION FEATURES
    # ------------------------------------------

    section_features = (
        get_section_entropy_features(
            pe_sample.get(
                "sections",
                []
            )
        )
    )

    row.update(section_features)

    # ------------------------------------------
    # IMPORT FEATURES
    # ------------------------------------------

    import_features = (
        extract_import_features(
            pe_sample.get(
                "imports",
                {}
            )
        )
    )

    row.update(import_features)

    # ------------------------------------------
    # ASM FEATURES
    # ------------------------------------------

    row["opcode_count"] = asm_sample.get(
        "opcode_count",
        0
    )

    row["string_count"] = asm_sample.get(
        "string_count",
        0
    )

    row["num_suspicious_strings"] = len(
        asm_sample.get(
            "suspicious_strings",
            []
        )
    )

    opcode_features = (
        extract_opcode_features(
            asm_sample.get(
                "top_opcodes",
                {}
            )
        )
    )

    row.update(opcode_features)

    port_features = (
        extract_port_features(
            asm_sample.get(
                "detected_ports",
                []
            )
        )
    )

    row.update(port_features)

    return row


# ==================================================
# DATASET BUILDING
# ==================================================

def build_dataset(
    pe_data,
    asm_data,
    label
):

    rows = []

    common_sha256s = (
        set(pe_data.keys())
        &
        set(asm_data.keys())
    )

    print(
        f"[INFO] {label}: "
        f"{len(common_sha256s)} matched samples"
    )

    for sha256 in common_sha256s:

        pe_sample = pe_data[sha256]
        asm_sample = asm_data[sha256]

        row = build_sample_features(
            pe_sample,
            asm_sample
        )

        row["sha256"] = sha256
        row["label"] = label

        rows.append(row)

    return rows


# ==================================================
# MAIN PREPROCESSING
# ==================================================

def preprocess(
    benign_pe_path,
    benign_asm_path,
    malware_pe_path,
    malware_asm_path,
    output_dir
):

    print("[INFO] Loading JSON files...")

    benign_pe = load_json(
        benign_pe_path
    )

    benign_asm = load_json(
        benign_asm_path
    )

    malware_pe = load_json(
        malware_pe_path
    )

    malware_asm = load_json(
        malware_asm_path
    )

    rows = []

    rows.extend(
        build_dataset(
            benign_pe,
            benign_asm,
            "benign"
        )
    )

    rows.extend(
        build_dataset(
            malware_pe,
            malware_asm,
            "malware"
        )
    )

    df = pd.DataFrame(rows)

    print(
        f"[INFO] Total samples: "
        f"{len(df)}"
    )

    df.fillna(0, inplace=True)

    # ------------------------------------------
    # LABELS
    # ------------------------------------------

    y = df["label"]

    X = df.drop(
        columns=[
            "label",
            "sha256"
        ],
        errors="ignore"
    )

    encoder = LabelEncoder()

    y_encoded = encoder.fit_transform(y)

    # ------------------------------------------
    # SPLIT
    # ------------------------------------------

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y_encoded,
            test_size=0.2,
            stratify=y_encoded,
            random_state=42
        )
    )

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    X_train.to_csv(
        os.path.join(
            output_dir,
            "X_train.csv"
        ),
        index=False
    )

    X_test.to_csv(
        os.path.join(
            output_dir,
            "X_test.csv"
        ),
        index=False
    )

    pd.DataFrame(
        y_train
    ).to_csv(
        os.path.join(
            output_dir,
            "y_train.csv"
        ),
        index=False
    )

    pd.DataFrame(
        y_test
    ).to_csv(
        os.path.join(
            output_dir,
            "y_test.csv"
        ),
        index=False
    )

    joblib.dump(
        encoder,
        os.path.join(
            output_dir,
            "label_encoder.pkl"
        )
    )

    print("[INFO] Preprocessing complete.")


# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":

    preprocess(
        BENIGN_PE_PATH,
        BENIGN_ASM_PATH,
        MALWARE_PE_PATH,
        MALWARE_ASM_PATH,
        OUTPUT_DIR
    )
