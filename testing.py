"""
Model evaluation script. Loads saved models + scaler and reports full metrics.
"""

import logging
import os

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    RocCurveDisplay, accuracy_score, classification_report,
    confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)

from data_preprocessing import run as preprocess

logging.basicConfig(
    filename="logs/ddos_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

TARGETS = ["attack", "normal"]


def load_artifacts():
    model = joblib.load("models/best_ddos_detector.pkl")
    scaler = joblib.load("models/scaler.pkl")
    return model, scaler


def full_report(model, scaler, X_test, y_test):
    X_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_scaled)
    y_proba = model.predict_proba(X_scaled)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    fp = confusion_matrix(y_test, y_pred)[0][1]
    total_neg = (y_test == 0).sum()
    fpr = fp / total_neg if total_neg else 0.0

    print("\n" + "=" * 60)
    print("DDoS Detection System — Model Evaluation Report")
    print("=" * 60)
    print(f"  Accuracy        : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  Precision       : {prec:.4f}")
    print(f"  Recall          : {rec:.4f}")
    print(f"  F1-Score        : {f1:.4f}")
    print(f"  ROC-AUC         : {auc:.6f}")
    print(f"  False Pos. Rate : {fpr:.4f}  ({fpr*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=TARGETS))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    _save_roc(model, X_scaled, y_test)
    _save_confusion(y_test, y_pred)

    logger.info(
        "Eval — acc=%.4f prec=%.4f rec=%.4f f1=%.4f auc=%.6f fpr=%.4f",
        acc, prec, rec, f1, auc, fpr,
    )
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "auc": auc, "fpr": fpr}


def _save_roc(model, X_scaled, y_test):
    fig, ax = plt.subplots(figsize=(8, 6))
    RocCurveDisplay.from_estimator(model, X_scaled, y_test, ax=ax)
    ax.set_title("ROC Curve — XGBoost DDoS Detector")
    fig.savefig("logs/roc_curve.png")
    plt.close(fig)


def _save_confusion(y_test, y_pred):
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    import seaborn as sns
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=TARGETS, yticklabels=TARGETS, ax=ax)
    ax.set_title("Confusion Matrix")
    ax.set_ylabel("True Label")
    ax.set_xlabel("Predicted Label")
    fig.savefig("logs/confusion_matrix.png")
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    _, X_test, _, y_test, _ = preprocess()
    model, scaler = load_artifacts()
    full_report(model, scaler, X_test, y_test)
