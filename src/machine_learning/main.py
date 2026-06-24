import argparse
import time

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

BENIGN_PE_PREDICT = "./output/benign_pe_predict_features.json"
BENIGN_ASM_PREDICT = "./output/benign_asm_predict_features.json"

MALWARE_PE_PREDICT = "./output/malware_pe_predict_features.json"
MALWARE_ASM_PREDICT = "./output/malware_asm_predict_features.json"


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

    evaluate(model_name)

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("PIPELINE COMPLETED")
    print("=" * 60)
    print(f"Total execution time: {elapsed:.2f} seconds")

def run_pipeline_predict(model_name):

    start_time = time.time()

    print("=" * 60)
    print("STEP 1: PREPROCESSING")
    print("=" * 60)

    preprocess_predict(
        benign_pe_path=BENIGN_PE_PREDICT,
        benign_asm_path=BENIGN_ASM_PREDICT,
        malware_pe_path=MALWARE_PE_PREDICT,
        malware_asm_path=MALWARE_ASM_PREDICT,
        output_dir=OUTPUT_DIR
    )

    print("=" * 60)
    print(f"STEP 2: EVALUATION ({model_name.upper()})")
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

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--model",
        choices=["rf", "xgb"],
        default="xgb",
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
            model_name=args.model
        )
