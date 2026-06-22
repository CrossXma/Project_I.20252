import argparse
import joblib
import os

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


# ==================================================
# CONFIG
# ==================================================

OUTPUT_DIR = "./output/dataset"
MODEL_DIR = "./output/models"

RANDOM_STATE = 42


# ==================================================
# DATA LOADING
# ==================================================

def load_training_data():

    x_path = os.path.join(
        OUTPUT_DIR,
        "X_train.csv"
    )

    y_path = os.path.join(
        OUTPUT_DIR,
        "y_train.csv"
    )

    X_train = pd.read_csv(x_path)

    y_train = pd.read_csv(
        y_path
    ).values.ravel()

    print(
        f"[INFO] Loaded "
        f"{len(X_train)} training samples"
    )

    print(
        f"[INFO] Number of features: "
        f"{X_train.shape[1]}"
    )

    return X_train, y_train


# ==================================================
# MODEL FACTORY
# ==================================================

def create_random_forest():

    return RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )


def create_xgboost():

    return XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        tree_method="hist"
    )


def get_model(model_name):

    if model_name == "rf":
        return create_random_forest()

    elif model_name == "xgb":
        return create_xgboost()

    else:
        raise ValueError(
            f"Unsupported model: {model_name}"
        )


# ==================================================
# TRAINING
# ==================================================

def train(model_name):

    print(
        f"[INFO] Training {model_name}"
    )

    X_train, y_train = load_training_data()

    model = get_model(model_name)

    model.fit(
        X_train,
        y_train
    )

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    model_path = os.path.join(
        MODEL_DIR,
        f"{model_name}.pkl"
    )

    joblib.dump(
        model,
        model_path
    )

    print(
        f"[INFO] Model saved:"
    )

    print(model_path)

    # ------------------------------------------
    # FEATURE IMPORTANCE
    # ------------------------------------------

    if hasattr(
        model,
        "feature_importances_"
    ):

        feature_importance = pd.DataFrame({
            "feature": X_train.columns,
            "importance": model.feature_importances_
        })

        feature_importance = (
            feature_importance
            .sort_values(
                "importance",
                ascending=False
            )
        )

        importance_path = os.path.join(
            MODEL_DIR,
            f"{model_name}_feature_importance.csv"
        )

        feature_importance.to_csv(
            importance_path,
            index=False
        )

        print(
            "[INFO] Feature importance saved:"
        )

        print(importance_path)


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
        required=True,
        help="Model type"
    )

    args = parser.parse_args()

    train(
        model_name=args.model
    )