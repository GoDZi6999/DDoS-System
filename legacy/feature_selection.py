"""
Feature importance analysis using mutual_info_classif (matches notebook section 5.3–5.4).
Run standalone to print/plot feature rankings; called by main.py during training.
"""

import logging
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.feature_selection import SelectKBest, mutual_info_classif

from data_preprocessing import run as preprocess, SELECTED_FEATURES

logger = logging.getLogger(__name__)


def compute_mutual_info(X_train: pd.DataFrame, y_train: pd.Series) -> pd.Series:
    scores = mutual_info_classif(X_train, y_train, random_state=42)
    mi = pd.Series(scores, index=X_train.columns).sort_values(ascending=False)
    return mi


def plot_importance(mi: pd.Series, out_path: str = "logs/feature_importance.png"):
    os.makedirs("logs", exist_ok=True)
    fig, ax = plt.subplots(figsize=(14, 5))
    mi.plot.bar(ax=ax, color="steelblue")
    ax.set_title("Feature Importance (Mutual Information)")
    ax.set_ylabel("MI Score")
    plt.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)
    logger.info("Feature importance plot saved to %s", out_path)


def select_k_best(X_train, y_train, X_test, k: int = 30):
    selector = SelectKBest(mutual_info_classif, k=k)
    selector.fit(X_train, y_train)
    selected = X_train.columns[selector.get_support()]
    return X_train[selected], X_test[selected], list(selected)


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, _ = preprocess()
    mi = compute_mutual_info(X_train, y_train)
    print(mi.to_string())
    print(f"\nTop-15 selected features:\n{SELECTED_FEATURES}")
    plot_importance(mi)
