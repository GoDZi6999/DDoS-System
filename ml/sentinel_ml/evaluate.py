"""Test-set metrics and plots."""

import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

BENIGN_INDEX = 0  # data.CLASSES[0] == "benign"


def _latency(pipeline: Pipeline, X: pd.DataFrame, repeats: int = 50) -> float:
    """Median milliseconds to classify one flow on its own (the real-time case)."""
    sample = X.iloc[:1]
    pipeline.predict_proba(sample)  # warm-up
    timings = []
    for _ in range(repeats):
        start = time.perf_counter()
        pipeline.predict_proba(sample)
        timings.append(time.perf_counter() - start)
    return float(np.median(timings) * 1000)


def evaluate(pipeline: Pipeline, X: pd.DataFrame, y: np.ndarray, classes: list[str]) -> dict:
    labels = list(range(len(classes)))
    start = time.perf_counter()
    proba = pipeline.predict_proba(X)
    batch_seconds = time.perf_counter() - start
    pred = proba.argmax(axis=1)

    precision, recall, f1, support = precision_recall_fscore_support(
        y, pred, labels=labels, zero_division=0
    )
    present = [i for i in labels if (y == i).any()]
    attack_true, attack_pred = y != BENIGN_INDEX, pred != BENIGN_INDEX
    benign_total = int((~attack_true).sum())
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "macro_precision": float(np.mean(precision[present])),
        "macro_recall": float(np.mean(recall[present])),
        "macro_f1": float(f1_score(y, pred, labels=present, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y, pred, average="weighted", zero_division=0)),
        "roc_auc_ovr_macro": float(
            np.mean([roc_auc_score(y == i, proba[:, i]) for i in present if (y != i).any()])
        ),
        "pr_auc_macro": float(
            np.mean([average_precision_score(y == i, proba[:, i]) for i in present])
        ),
        # SOC view: any attack flagged as some attack, and benign flows raising alarms.
        "attack_detection_rate": float(
            (attack_pred & attack_true).sum() / max(attack_true.sum(), 1)
        ),
        "false_positive_rate": float((attack_pred & ~attack_true).sum() / max(benign_total, 1)),
        "per_class": {
            cls: {
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i, cls in enumerate(classes)
        },
        "confusion_matrix": confusion_matrix(y, pred, labels=labels).tolist(),
        "batch_us_per_flow": batch_seconds / max(len(X), 1) * 1e6,
        "single_flow_ms": _latency(pipeline, X),
    }


def plot_confusion_matrix(matrix: list[list[int]], classes: list[str], path: Path) -> None:
    counts = np.asarray(matrix, dtype=float)
    normalised = counts / np.maximum(counts.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(normalised, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(
                j,
                i,
                f"{normalised[i, j]:.2f}",
                ha="center",
                va="center",
                color="white" if normalised[i, j] > 0.5 else "black",
                fontsize=8,
            )
    fig.colorbar(image, ax=ax, fraction=0.046, label="Share of actual class")
    ax.set_title("Confusion matrix (row-normalised, test set)")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def plot_importance(importance: pd.Series, path: Path, top: int = 15) -> None:
    data = importance.head(top)[::-1]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(data.index, data.to_numpy(), color="#2a6fdb")
    ax.set_xlabel("Mean |SHAP value| (summed over classes)")
    ax.set_title(f"Top {top} features (SHAP, test sample)")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
