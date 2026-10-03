"""Versioned model bundles: models/<name>/<version>/

    model.joblib          fitted Pipeline (shared preprocessing + estimator)
    background.joblib     small sample of training flows for SHAP
    feature_config.json   ordered feature list with units, class list
    model_metadata.json   dataset digest, split, params, metrics, versions, checksums

joblib files are pickles: loading one runs code, so only load bundles you
built or trust. load_bundle verifies the recorded SHA-256 checksums first,
and refuses a bundle whose feature list differs from the current code.
"""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
from sklearn.pipeline import Pipeline

from sentinel_ml.features import FEATURE_NAMES, FEATURES

MODEL_FILE = "model.joblib"
BACKGROUND_FILE = "background.joblib"
FEATURES_FILE = "feature_config.json"
METADATA_FILE = "model_metadata.json"


class BundleError(Exception):
    pass


@dataclass
class Bundle:
    path: Path
    pipeline: Pipeline
    classes: list[str]
    background: pd.DataFrame
    metadata: dict

    @property
    def version(self) -> str:
        return self.metadata["version"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_bundle(
    directory: Path,
    pipeline: Pipeline,
    classes: list[str],
    background: pd.DataFrame,
    metadata: dict,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, directory / MODEL_FILE, compress=3)
    joblib.dump(background[list(FEATURE_NAMES)], directory / BACKGROUND_FILE, compress=3)
    feature_config = {
        "features": [
            {"name": f.name, "description": f.description, "cic_column": f.cic_column}
            for f in FEATURES
        ],
        "classes": classes,
    }
    (directory / FEATURES_FILE).write_text(json.dumps(feature_config, indent=2))
    metadata = metadata | {
        "checksums": {
            MODEL_FILE: _sha256(directory / MODEL_FILE),
            BACKGROUND_FILE: _sha256(directory / BACKGROUND_FILE),
        }
    }
    (directory / METADATA_FILE).write_text(json.dumps(metadata, indent=2, default=str))
    return directory


def load_bundle(directory: Path) -> Bundle:
    directory = Path(directory)
    try:
        metadata = json.loads((directory / METADATA_FILE).read_text())
        feature_config = json.loads((directory / FEATURES_FILE).read_text())
    except FileNotFoundError as exc:
        raise BundleError(f"not a model bundle: {directory}") from exc

    for name, expected in metadata.get("checksums", {}).items():
        if _sha256(directory / name) != expected:
            raise BundleError(f"checksum mismatch for {name}; refusing to load")
    names = tuple(f["name"] for f in feature_config["features"])
    if names != FEATURE_NAMES:
        raise BundleError("bundle was trained on a different feature definition")

    return Bundle(
        path=directory,
        pipeline=joblib.load(directory / MODEL_FILE),
        classes=list(feature_config["classes"]),
        background=joblib.load(directory / BACKGROUND_FILE),
        metadata=metadata,
    )
