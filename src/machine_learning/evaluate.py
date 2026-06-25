import argparse
import joblib
import os
import time

import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)


# ==================================================
# CONFIG
# ==================================================

DATASET_DIR = "./output/dataset"
MODEL_DIR = "./output/models"
RESULT_DIR = "./output/results"


# ==================================================
# LOAD DATA
# ==================================================

def load_test_data(option):

    X_test = pd.read_csv(
        os.path.join(
            DATASET_DIR,
            f"X_{option}.csv"
        )
    )

    y_test = pd.read_csv(
        os.path.join(
            DATASET_DIR,
            f"y_{option}.csv"
        )
    ).values.ravel()

    return X_test, y_test


def load_label_encoder():

    encoder_path = os.path.join(
        DATASET_DIR,
        "label_encoder.pkl"
    )

    return joblib.load(
        encoder_path
    )


def load_model(model_name):

    model_path = os.path.join(
        MODEL_DIR,
        f"{model_name}.pkl"
    )

    return joblib.load(
        model_path
    )


# ==================================================
# Details
# ==================================================
def detailed_output(model_name, option, results_df, prediction_path):

    # print("\n========== DETAILS ==========")
    # print("=" * 80)

    # for _, row in results_df.iterrows():

    #     print(
    #         f"{row['file_name'][:6]:<10}"
    #         f"{row['sha256'][:6]:<10}"
    #         f"{row['prediction']:<12}"
    #         f"{row['confidence']:>7}%"
    #     )

    results_df.to_csv(
        prediction_path,
        index=False
    )


# ==================================================
# EVALUATION
# ==================================================

def evaluate(model_name, option):

    print(
        f"[INFO] Evaluating {model_name}"
    )

    X_test, y_test = load_test_data(option=option)

    encoder = load_label_encoder()

    model = load_model(model_name)

    # ------------------------------------------
    # Predictions
    # ------------------------------------------

    start_time = time.time()

    y_pred = model.predict(X_test)

    runtime = time.time() - start_time

    # ------------------------------------------
    # Metrics
    # ------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted"
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted"
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted"
    )

    probabilities = model.predict_proba(
        X_test
    )

    confidence_scores = (
        probabilities.max(axis=1)
    )

    # ------------------------------------------
    # Human-readable labels
    # ------------------------------------------

    y_test_labels = (
        encoder.inverse_transform(
            y_test
        )
    )

    y_pred_labels = (
        encoder.inverse_transform(
            y_pred
        )
    )

    report = classification_report(
        y_test_labels,
        y_pred_labels
    )

    cm = confusion_matrix(
        y_test_labels,
        y_pred_labels
    )

    metadata = pd.read_csv(
        os.path.join(
            DATASET_DIR,
            f"{option}_metadata.csv"
        )
    )

    results_df = pd.DataFrame({

        "file_name":
            metadata["file_name"],

        "sha256":
            metadata["sha256"],

        "prediction":
            y_pred_labels,

        "confidence":
            confidence_scores
    })

    results_df["confidence"] = (
        results_df["confidence"] * 100
    ).round(2)

    prediction_path = os.path.join(
        RESULT_DIR,
        f"{model_name}_{option}_predictions.csv"
    )

    # ------------------------------------------
    # Print
    # ------------------------------------------

    print("\n========== RESULTS ==========")

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print("\nClassification Report")

    print(report)

    print("\nConfusion Matrix")

    print(cm)

    detailed_output(model_name, option, results_df, prediction_path)

    # ------------------------------------------
    # Save results
    # ------------------------------------------

    os.makedirs(
        RESULT_DIR,
        exist_ok=True
    )

    metrics_path = os.path.join(
        RESULT_DIR,
        f"{model_name}_metrics_{option}.txt"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8"
    ) as f:
        
        f.write("Prediction Runtime Metrics\n")
        f.write("--------------------------\n")
        
        f.write(
            f"Model: {model_name}\n"
        )

        f.write(
            f"Samples: {len(results_df)}\n"
        )

        f.write(
            f"Runtime: {runtime:.4f} seconds\n"
        )

        f.write(
            f"Average per sample: "
            f"{runtime / len(results_df):.6f} seconds\n"
        )

        f.write("\nClassification Metrics\n")
        f.write("----------------------\n")

        f.write(
            f"Accuracy : {accuracy:.4f}\n"
        )

        f.write(
            f"Precision: {precision:.4f}\n"
        )

        f.write(
            f"Recall   : {recall:.4f}\n"
        )

        f.write(
            f"F1 Score : {f1:.4f}\n\n"
        )

        f.write(
            "Classification Report\n"
        )

        f.write(report)

        f.write(
            "\n\nConfusion Matrix\n"
        )

        f.write(str(cm))

    print(
        "\n[INFO] Results saved:"
    )

    print(metrics_path)
    print(prediction_path)


# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--model",
        choices=[
            "rf",
            "xgb"
        ],
        required=True
    )

    parser.add_argument(
        "--option",
        choices=[
            "test",
            "predict"
        ],
        default="test"
    )

    args = parser.parse_args()

    evaluate(
        model_name=args.model,
        option=args.option
    )
