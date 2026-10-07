"""Candidate models. Every model is a scikit-learn Pipeline whose first step is
the shared FlowPreprocessor, so preprocessing is saved with the model and can
never drift between training and inference."""

from collections.abc import Callable

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from argus_ml.features import FEATURE_NAMES


class FlowPreprocessor(BaseEstimator, TransformerMixin):
    """Select the features in canonical order; signed log1p tames heavy tails
    (rates and byte counts span ~10 orders of magnitude). Monotonic, so tree
    models are unaffected; it mainly helps the linear baseline."""

    def fit(self, X: pd.DataFrame, y=None) -> "FlowPreprocessor":
        return self

    def __sklearn_is_fitted__(self) -> bool:
        return True  # stateless: usable without fitting (e.g. as a sliced pipeline step)

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        values = X[list(FEATURE_NAMES)].to_numpy(dtype=np.float64)
        return np.sign(values) * np.log1p(np.abs(values))

    def get_feature_names_out(self, input_features=None) -> np.ndarray:
        return np.asarray(FEATURE_NAMES, dtype=object)


def logistic_regression(seed: int) -> Pipeline:
    return Pipeline(
        [
            ("features", FlowPreprocessor()),
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed),
            ),
        ]
    )


def random_forest(seed: int) -> Pipeline:
    return Pipeline(
        [
            ("features", FlowPreprocessor()),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=seed,
                ),
            ),
        ]
    )


def xgboost(seed: int) -> Pipeline:
    return Pipeline(
        [
            ("features", FlowPreprocessor()),
            (
                "model",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.1,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    tree_method="hist",
                    n_jobs=-1,
                    random_state=seed,
                ),
            ),
        ]
    )


CANDIDATES: dict[str, Callable[[int], Pipeline]] = {
    "logistic_regression": logistic_regression,
    "random_forest": random_forest,
    "xgboost": xgboost,
}


class AblationPreprocessor(FlowPreprocessor):
    """FlowPreprocessor without some features; used for ablation studies only
    (bundled models always use the full feature set)."""

    def __init__(self, drop: tuple[str, ...] = ()) -> None:
        self.drop = drop

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        columns = [f for f in FEATURE_NAMES if f not in self.drop]
        values = X[columns].to_numpy(dtype=np.float64)
        return np.sign(values) * np.log1p(np.abs(values))


def without_features(pipeline: Pipeline, drop: tuple[str, ...]) -> Pipeline:
    return Pipeline([("features", AblationPreprocessor(drop)), *pipeline.steps[1:]])


def fit(pipeline: Pipeline, X: pd.DataFrame, y: np.ndarray, weighting: str = "sqrt") -> Pipeline:
    """Fit a candidate. Benign is kept in full, so XGBoost sees realistic base
    rates; "sqrt" sample weights (square root of balanced) keep rare attack
    classes from being swamped without pretending they are as common as
    benign. "balanced" and "none" are the two extremes. The linear and forest
    baselines balance internally (class_weight)."""
    params = {}
    if weighting != "none" and isinstance(pipeline[-1], XGBClassifier):
        weights = compute_sample_weight("balanced", y)
        params["model__sample_weight"] = np.sqrt(weights) if weighting == "sqrt" else weights
    return pipeline.fit(X, y, **params)


def is_tree_model(pipeline: Pipeline) -> bool:
    return isinstance(pipeline[-1], (RandomForestClassifier, XGBClassifier))
