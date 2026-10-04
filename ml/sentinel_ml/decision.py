"""Turning class probabilities into a label.

Plain argmax treats a 51% "botnet" like a 99% one. In a SOC, where benign
traffic outnumbers each rare attack class by 1,000:1, that floods analysts
with false positives. The bundle therefore stores one weight per class, tuned
on a validation set with the real class mix; the label is
argmax(probability x weight). Weights only ever go down from 1 (the benign
weight stays 1), so tuning can make the model more conservative about an
attack class but never more eager than argmax.
"""

from itertools import pairwise

import numpy as np
from sklearn.metrics import f1_score

GRID = np.geomspace(0.01, 1.0, 41)
BENIGN_INDEX = 0


def decide(proba: np.ndarray, weights: np.ndarray | None = None) -> np.ndarray:
    return proba.argmax(axis=1) if weights is None else (proba * weights).argmax(axis=1)


def macro_f1(y: np.ndarray, pred: np.ndarray) -> float:
    present = np.unique(y)
    return float(f1_score(y, pred, labels=present, average="macro", zero_division=0))


def tune_weights(proba: np.ndarray, y: np.ndarray, rounds: int = 3) -> np.ndarray:
    """Coordinate search over attack-class weights for the best macro-F1."""
    weights = np.ones(proba.shape[1])
    best = macro_f1(y, decide(proba, weights))
    for _ in range(rounds):
        improved = False
        for cls in range(proba.shape[1]):
            if cls == BENIGN_INDEX:
                continue
            for value in GRID:
                trial = weights.copy()
                trial[cls] = value
                score = macro_f1(y, decide(proba, trial))
                if score > best + 1e-9:
                    best, weights, improved = score, trial, True
        if not improved:
            break
    return weights


def expected_calibration_error(
    proba: np.ndarray, y: np.ndarray, weights: np.ndarray | None = None, bins: int = 10
) -> float:
    """Gap between the confidence reported for the predicted class and how
    often that prediction is right, averaged over confidence bins."""
    pred = decide(proba, weights)
    confidence = proba[np.arange(len(pred)), pred]
    edges = np.linspace(0, 1, bins + 1)
    error = 0.0
    for low, high in pairwise(edges):
        mask = (confidence > low) & (confidence <= high)
        if mask.any():
            error += mask.mean() * abs((pred[mask] == y[mask]).mean() - confidence[mask].mean())
    return float(error)
