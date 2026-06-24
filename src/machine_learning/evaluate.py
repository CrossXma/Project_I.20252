import argparse
import joblib
import os

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

    y_pred = model.predict(X_test)

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
