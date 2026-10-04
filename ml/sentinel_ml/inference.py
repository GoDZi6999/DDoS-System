"""Inference API used by the real-time ML engine (Phase 5) and the CLI.

predictor = Predictor.from_bundle("models/sentinel-flow/2026.10.03")
for p in predictor.predict(features.from_records(flows)):
    print(p.label, f"{p.confidence:.1%}")   # e.g. "ddos 97.4%"
"""

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from sentinel_ml.bundle import Bundle, load_bundle
from sentinel_ml.explain import Explainer

BENIGN = "benign"


@dataclass
class Prediction:
    label: str
    confidence: float
    class_probs: dict[str, float]
    explanation: list[dict] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.label != BENIGN

    def summary(self) -> str:
        if not self.is_attack:
            return f"Benign traffic — confidence {self.confidence:.1%}"
        return f"{self.label} detected — confidence {self.confidence:.1%}"


class Predictor:
    def __init__(self, bundle: Bundle, top_k: int = 5) -> None:
        self.bundle = bundle
        self.top_k = top_k
        self._explainer: Explainer | None = None

    @classmethod
    def from_bundle(cls, path: str | Path, top_k: int = 5) -> "Predictor":
        return cls(load_bundle(Path(path)), top_k=top_k)

    @property
    def explainer(self) -> Explainer:
        if self._explainer is None:  # SHAP setup is slow; only pay for it when needed
            self._explainer = Explainer(self.bundle.pipeline, self.bundle.background)
        return self._explainer

    def predict(self, features: pd.DataFrame, explain: str = "attacks") -> list[Prediction]:
        """explain: "attacks" (default, cheapest useful), "all" or "none"."""
        proba = self.bundle.pipeline.predict_proba(features)
        best = proba.argmax(axis=1)
        classes = self.bundle.classes
        predictions = [
            Prediction(
                label=classes[i],
                confidence=round(float(row[i]), 4),
                class_probs={c: round(float(p), 4) for c, p in zip(classes, row, strict=True)},
            )
            for row, i in zip(proba, best, strict=True)
        ]
        if explain != "none":
            rows = np.arange(len(predictions))
            if explain == "attacks":
                rows = np.flatnonzero([p.is_attack for p in predictions])
            self.explain_rows(features, predictions, rows)
        return predictions

    def explain_rows(
        self, features: pd.DataFrame, predictions: list[Prediction], rows: np.ndarray
    ) -> None:
        """Attach SHAP explanations to the selected predictions (towards their
        predicted class). Lets callers explain a sample when a flood would make
        explaining every flow too slow."""
        rows = np.asarray(rows, dtype=int)
        if not len(rows):
            return
        classes = list(self.bundle.classes)
        targets = np.array([classes.index(predictions[r].label) for r in rows])
        explanations = self.explainer.explain(features.iloc[rows], targets, top_k=self.top_k)
        for row, items in zip(rows, explanations, strict=True):
            predictions[row].explanation = items
