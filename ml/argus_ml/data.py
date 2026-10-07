"""Load, clean and split CIC-IDS2017 (MachineLearningCVE CSVs).

Cleaning (each step is counted in the returned report):
1. strip column names, normalise labels, map them to Argus classes;
   classes too rare to learn (Infiltration, Heartbleed) are dropped;
2. drop rows with a negative flow duration (CICFlowMeter bug);
3. drop exact duplicates, and every copy of a feature vector that appears
   with different labels (ambiguous).

Splitting: rows of each (source file, label) group are kept in capture order,
the first TRAIN_FRACTION goes to training and the rest to test. Attack runs
produce near-identical consecutive flows, so a random row split would leak
them into the test set and inflate scores. Training rows also get a `fold`
(0..n_folds-1) made of contiguous chunks per group, for blocked cross-validation.
"""

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from argus_ml.features import CIC_COLUMNS, FEATURE_NAMES, from_cic

TRAIN_FRACTION = 0.7

# CIC label (normalised: lowercase, non-alphanumerics collapsed) -> Argus class.
LABEL_MAP = {
    "benign": "benign",
    "ddos": "ddos",
    "dos hulk": "dos",
    "dos goldeneye": "dos",
    "dos slowloris": "dos",
    "dos slowhttptest": "dos",
    "portscan": "portscan",
    "ftp patator": "bruteforce",
    "ssh patator": "bruteforce",
    "web attack brute force": "webattack",
    "web attack xss": "webattack",
    "web attack sql injection": "webattack",
    "bot": "botnet",
}
DROPPED_LABELS = {"infiltration", "heartbleed"}
CLASSES = ("benign", "ddos", "dos", "portscan", "bruteforce", "webattack", "botnet")


def normalise_label(raw: str) -> str:
    # Collapses the mis-encoded dash in "Web Attack � Brute Force" as well.
    return re.sub(r"[^a-z0-9]+", " ", raw.lower()).strip()


@dataclass
class Dataset:
    features: pd.DataFrame  # columns = FEATURE_NAMES
    labels: pd.Series  # Argus class names
    groups: pd.Series  # "<file>|<original label>", used for splitting
    report: dict = field(default_factory=dict)


@dataclass
class Split:
    X_train: pd.DataFrame
    y_train: pd.Series
    folds: np.ndarray
    X_test: pd.DataFrame
    y_test: pd.Series


def file_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode())
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()


def load_cic_csvs(paths: list[Path]) -> tuple[pd.DataFrame, list[str]]:
    frames = []
    for path in sorted(paths):
        frame = pd.read_csv(path, encoding="latin-1", low_memory=False)
        frame.columns = [c.strip() for c in frame.columns]
        frame["source_file"] = path.name
        frames.append(frame[[*CIC_COLUMNS, "Label", "source_file"]])
    if not frames:
        raise FileNotFoundError("no CSV files given")
    return pd.concat(frames, ignore_index=True), [p.name for p in sorted(paths)]


def prepare(raw: pd.DataFrame) -> Dataset:
    report: dict = {"rows_loaded": len(raw)}
    normalised = raw["Label"].astype(str).map(normalise_label)
    unknown = sorted(set(normalised) - set(LABEL_MAP) - DROPPED_LABELS)
    if unknown:
        raise ValueError(f"unmapped labels: {unknown}")

    keep = ~normalised.isin(DROPPED_LABELS)
    report["dropped_rare_classes"] = int((~keep).sum())
    raw, normalised = raw[keep], normalised[keep]

    features = from_cic(raw)
    valid = features["flow_duration_s"] >= 0
    report["dropped_negative_duration"] = int((~valid).sum())
    features, raw, normalised = features[valid], raw[valid], normalised[valid]

    labels = normalised.map(LABEL_MAP)
    frame = features.assign(label=labels)
    exact_dupes = frame.duplicated(keep="first")
    report["dropped_exact_duplicates"] = int(exact_dupes.sum())
    frame, raw, normalised = frame[~exact_dupes], raw[~exact_dupes], normalised[~exact_dupes]
    conflicting = frame.duplicated(subset=list(FEATURE_NAMES), keep=False)
    report["dropped_conflicting_labels"] = int(conflicting.sum())
    frame, raw, normalised = frame[~conflicting], raw[~conflicting], normalised[~conflicting]

    report["rows_kept"] = len(frame)
    report["class_counts"] = frame["label"].value_counts().to_dict()
    return Dataset(
        features=frame[list(FEATURE_NAMES)].reset_index(drop=True),
        labels=frame["label"].reset_index(drop=True),
        groups=(raw["source_file"] + "|" + normalised).reset_index(drop=True),
        report=report,
    )


def temporal_split(dataset: Dataset, n_folds: int = 5) -> Split:
    """Per (file, label) group: first 70% (capture order) -> train, rest -> test."""
    position = dataset.groups.groupby(dataset.groups).cumcount()
    size = dataset.groups.map(dataset.groups.value_counts())
    cut = np.floor(size * TRAIN_FRACTION)
    is_train = (position < cut).to_numpy()
    folds = np.minimum((position / cut.clip(lower=1) * n_folds).astype(int), n_folds - 1)
    return Split(
        X_train=dataset.features[is_train].reset_index(drop=True),
        y_train=dataset.labels[is_train].reset_index(drop=True),
        folds=folds[is_train].to_numpy(),
        X_test=dataset.features[~is_train].reset_index(drop=True),
        y_test=dataset.labels[~is_train].reset_index(drop=True),
    )


def cap_per_class(
    X: pd.DataFrame,
    y: pd.Series,
    cap: int,
    seed: int,
    folds: np.ndarray | None = None,
    uncapped: tuple[str, ...] = (),
) -> tuple[pd.DataFrame, pd.Series, np.ndarray | None]:
    """Random sample of at most `cap` rows per class (keeps training time
    bounded); classes in `uncapped` are kept in full."""
    rng = np.random.default_rng(seed)
    chosen = []
    for label in y.unique():
        index = np.flatnonzero((y == label).to_numpy())
        if label not in uncapped and len(index) > cap:
            index = rng.choice(index, size=cap, replace=False)
        chosen.append(index)
    order = np.sort(np.concatenate(chosen))
    return (
        X.iloc[order].reset_index(drop=True),
        y.iloc[order].reset_index(drop=True),
        None if folds is None else folds[order],
    )
