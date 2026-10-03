"""
Model training: XGBoost (primary) + Logistic Regression (baseline).
Uses best hyperparameters found via GridSearchCV in the notebook.
"""

import logging
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)

# Best params from notebook GridSearchCV
XGB_BEST_PARAMS = {
    "colsample_bytree": 0.5,
    "learning_rate": 0.1,
    "max_depth": 6,
    "n_estimators": 128,
    "subsample": 0.8,
    "random_state": 42,
    "eval_metric": "logloss",
    "use_label_encoder": False,
}


def scale(X_train, X_test):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.pkl")
    logger.info("Scaler saved to models/scaler.pkl")
    return X_train_scaled, X_test_scaled, scaler


def train_xgb(X_train, y_train) -> XGBClassifier:
    model = XGBClassifier(**XGB_BEST_PARAMS)
    model.fit(X_train, y_train)
    logger.info("XGBoost training complete.")
    return model


def train_logistic(X_train, y_train) -> LogisticRegression:
    model = LogisticRegression(random_state=42, max_iter=1000)
    model.fit(X_train, y_train)
    logger.info("Logistic Regression training complete.")
    return model


def evaluate(model, X_test, y_test, name: str = "Model") -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "auc_roc": roc_auc_score(y_test, y_proba),
    }

    print(f"\n{'='*50}\n{name} — Evaluation\n{'='*50}")
    print(classification_report(y_test, y_pred, target_names=["attack", "normal"]))
    print(f"ROC-AUC: {metrics['auc_roc']:.6f}")
    print(confusion_matrix(y_test, y_pred))

    logger.info(
        "%s — acc=%.4f f1=%.4f auc=%.6f",
        name, metrics["accuracy"], metrics["f1"], metrics["auc_roc"],
    )
    return metrics


def save_model(model, path: str):
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, path)
    logger.info("Model saved to %s", path)


def run(X_train, X_test, y_train, y_test):
    X_train_s, X_test_s, scaler = scale(X_train, X_test)

    xgb = train_xgb(X_train_s, y_train)
    lr = train_logistic(X_train_s, y_train)

    xgb_metrics = evaluate(xgb, X_test_s, y_test, "XGBoost")
    lr_metrics = evaluate(lr, X_test_s, y_test, "Logistic Regression")

    # Save best model (XGBoost is always best per notebook findings)
    save_model(xgb, "models/best_ddos_detector.pkl")
    save_model(lr, "models/logistic_regression.pkl")

    return xgb, lr, scaler, xgb_metrics, lr_metrics


if __name__ == "__main__":
    import os
    os.makedirs("logs", exist_ok=True)
    from data_preprocessing import run as preprocess
    X_train, X_test, y_train, y_test, _ = preprocess()
    run(X_train, X_test, y_train, y_test)
