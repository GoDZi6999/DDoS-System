"""Per-prediction explanations with SHAP.

For each flow, the features that pushed the model towards its predicted class
are returned with their signed SHAP value and their share of the total
absolute attribution (`weight`, percent), which is what the dashboard shows:

    Packet rate      ██████████  38%
    SYN flag count   ███████     27%

SHAP explains the model's reasoning, not ground-truth causality.
"""

import numpy as np
import pandas as pd
import shap
from sklearn.pipeline import Pipeline

from sentinel_ml.features import FEATURE_NAMES
from sentinel_ml.models import is_tree_model


class Explainer:
    def __init__(self, pipeline: Pipeline, background: pd.DataFrame) -> None:
        self.preprocess = pipeline[:-1]
        estimator = pipeline[-1]
        if is_tree_model(pipeline):
            self._explainer = shap.TreeExplainer(estimator)
        else:
            self._explainer = shap.LinearExplainer(estimator, self.preprocess.transform(background))

    def _values(self, X: pd.DataFrame) -> np.ndarray:
        """SHAP values as (rows, features, classes)."""
        values = self._explainer.shap_values(self.preprocess.transform(X))
        if isinstance(values, list):
            values = np.stack(values, axis=-1)
        return np.asarray(values)

    def explain(
        self, X: pd.DataFrame, class_indices: np.ndarray, top_k: int = 5
    ) -> list[list[dict]]:
        values = self._values(X)
        raw = X[list(FEATURE_NAMES)].to_numpy(dtype=np.float64)
        explanations = []
        for row, cls in enumerate(class_indices):
            contributions = values[row, :, cls]
            total = np.abs(contributions).sum() or 1.0
            top = np.argsort(-contributions)[:top_k]  # strongest push towards the class
            explanations.append(
                [
                    {
                        "feature": FEATURE_NAMES[i],
                        "value": float(raw[row, i]),
                        "contribution": float(contributions[i]),
                        "weight": round(float(abs(contributions[i]) / total * 100), 2),
                    }
                    for i in top
                    if contributions[i] > 0
                ]
            )
        return explanations

    def global_importance(self, X: pd.DataFrame) -> pd.Series:
        """Mean |SHAP| per feature, summed over classes."""
        values = np.abs(self._values(X)).mean(axis=0).sum(axis=-1)
        return pd.Series(values, index=FEATURE_NAMES).sort_values(ascending=False)
