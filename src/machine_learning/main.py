import argparse
import time
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# try:
from src.pe_extractor.pe_extractor import process_multiple_files as extract_pe
from src.asm_extractor.asm_extractor import process_multiple_files as extract_asm
# except ImportError:
#     extract_pe = None
#     extract_asm = None
from preprocessing import preprocess, preprocess_predict
from train import train
from evaluate import evaluate


# ==================================================
# DATASET PATHS
# ==================================================

BENIGN_PE = "./output/benign_pe_features.json"
BENIGN_ASM = "./output/benign_asm_features.json"

MALWARE_PE = "./output/malware_pe_features.json"
MALWARE_ASM = "./output/malware_asm_features.json"

OUTPUT_DIR = "./output/dataset"
OUTPUT_JSON_DIR = "./output/json"

MALWARE_PE_PREDICT = "./output/json/malware_pe_predict_features.json"
MALWARE_ASM_PREDICT = "./output/json/malware_asm_predict_features.json"


# ==================================================
# EXTRACT
# ==================================================

def extract_file(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    if extract_pe is None or extract_asm is None:
        print("Error: Extraction modules not available.")
        return

    output_json_path = os.path.join(OUTPUT_JSON_DIR, os.path.basename(file_path))

    # Extract PE features
    extract_pe([file_path], os.path.join(output_json_path + "_pe_features.json"))

    # Extract ASM features
    extract_asm([file_path], os.path.join(output_json_path + "_asm_features.json"))

def extract_directory(dir_path):
    if not os.path.exists(dir_path):
        print(f"Error: Directory not found at {dir_path}")
        return

    if extract_pe is None or extract_asm is None:
        print("Error: Extraction modules not available.")
        return

    # Find all executable files recursively
    executables = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.lower().endswith(('.exe', '.dll', '.sys', '.zip')):
                executables.append(os.path.join(root, file))

    if not executables:
        print("No executable files (.exe, .dll, .sys, .zip) found in directory.")
        return

    print(f"Found {len(executables)} executable files. Extracting...")

    extract_pe(executables, MALWARE_PE_PREDICT)
    extract_asm(executables, MALWARE_ASM_PREDICT)


# ==================================================
# PIPELINE
# ==================================================

def run_pipeline(model_name):

    start_time = time.time()

    print("=" * 60)
    print("STEP 1: PREPROCESSING")
    print("=" * 60)

    preprocess(
        benign_pe_path=BENIGN_PE,
        benign_asm_path=BENIGN_ASM,
        malware_pe_path=MALWARE_PE,
        malware_asm_path=MALWARE_ASM,
        output_dir=OUTPUT_DIR
    )

    print()

    print("=" * 60)
    print(f"STEP 2: TRAINING ({model_name.upper()})")
    print("=" * 60)

    train(model_name)

    print()

    print("=" * 60)
    print(f"STEP 3: EVALUATION ({model_name.upper()})")
    print("=" * 60)

    evaluate(model_name, option="test")

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("PIPELINE COMPLETED")
    print("=" * 60)
    print(f"Total execution time: {elapsed:.2f} seconds")

def run_pipeline_predict(model_name, path):

    start_time = time.time()

    print("=" * 60)
    print("STEP 1: EXTRACTING")
    print("=" * 60)

    malware_pe_path = MALWARE_PE_PREDICT
    malware_asm_path = MALWARE_ASM_PREDICT

    if path:
        if os.path.isdir(path):
            extract_directory(path)
        else:
            extract_file(path)
            malware_pe_path = os.path.join(OUTPUT_JSON_DIR, os.path.basename(path) + "_pe_features.json")
            malware_asm_path = os.path.join(OUTPUT_JSON_DIR, os.path.basename(path) + "_asm_features.json")

    print("=" * 60)
    print("STEP 2: PREPROCESSING")
    print("=" * 60)

    preprocess_predict(
        malware_pe_path=malware_pe_path,
        malware_asm_path=malware_asm_path,
        output_dir=OUTPUT_DIR
    )

    print("=" * 60)
    print(f"STEP 3: EVALUATION ({model_name.upper()})")
    print("=" * 60)

    evaluate(model_name, option="predict")

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("PIPELINE COMPLETED")
    print("=" * 60)
    print(f"Total execution time: {elapsed:.2f} seconds")


# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Specify path if evaluating malware files or datasets.")
    parser.add_argument("--path", nargs="?", default=None,
                        help="Path to an executable file or a directory to evaluate statically.")
    
    parser.add_argument(
        "--model",
        choices=["rf", "xgb"],
        required=True,
        help="Machine learning model"
    )

    parser.add_argument(
        "--option",
        choices=[
            "test",
            "predict"
        ],
        default="test",
        help="Run option"
    )

    args = parser.parse_args()

    if args.option == "test":
        run_pipeline(
            model_name=args.model
        )
    else:
        run_pipeline_predict(
            model_name=args.model,
            path=args.path
        )
