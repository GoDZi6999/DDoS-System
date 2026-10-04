"""Synthetic CIC-IDS2017-format CSVs, so the pipeline can be tested without the
real dataset. They reproduce its quirks: padded column names, extra columns,
Infinity rates, duplicates, a negative duration, the mis-encoded web-attack
label and a class too rare to learn."""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sentinel_ml.features import CIC_COLUMNS

# file name -> [(CIC label, rows)]
FILES = {
    "Friday-DDos.csv": [("BENIGN", 160), ("DDoS", 120)],
    "Wednesday.csv": [("BENIGN", 160), ("DoS Hulk", 90), ("DoS slowloris", 40), ("PortScan", 120)],
    "Tuesday.csv": [
        ("BENIGN", 160),
        ("FTP-Patator", 60),
        ("SSH-Patator", 60),
        ("Web Attack � Brute Force", 100),
        ("Bot", 100),
        ("Infiltration", 5),
    ],
}
SIGNATURE = {  # class-specific shift of the log-mean, per column (seeded)
    label: np.random.default_rng(i).normal(0, 2.5, len(CIC_COLUMNS))
    for i, label in enumerate(
        [
            "BENIGN",
            "DDoS",
            "DoS Hulk",
            "DoS slowloris",
            "PortScan",
            "FTP-Patator",
            "SSH-Patator",
            "Web Attack � Brute Force",
            "Bot",
            "Infiltration",
        ]
    )
}


def synthetic_frame(label: str, rows: int, rng: np.random.Generator) -> pd.DataFrame:
    shift = SIGNATURE[label]
    values = np.exp(rng.normal(4 + shift, 0.4, size=(rows, len(CIC_COLUMNS))))
    frame = pd.DataFrame(np.round(values), columns=list(CIC_COLUMNS))
    frame["Label"] = label
    return frame


def write_dataset(directory: Path, seed: int = 0) -> Path:
    rng = np.random.default_rng(seed)
    directory.mkdir(parents=True, exist_ok=True)
    for name, parts in FILES.items():
        frame = pd.concat([synthetic_frame(lbl, n, rng) for lbl, n in parts], ignore_index=True)
        frame.loc[0, "Flow Duration"] = 0  # rates must come out as 0, not Infinity
        frame.loc[1, "Flow Duration"] = -5  # CICFlowMeter bug: dropped
        frame = pd.concat([frame, frame.iloc[[2, 3]]], ignore_index=True)  # duplicates
        frame.insert(0, "Destination Port", 80)  # extra column the loader must ignore
        frame["Flow Bytes/s"] = np.inf
        frame.columns = [f" {c}" for c in frame.columns]  # CIC pads names with spaces
        frame.to_csv(directory / name, index=False)
    return directory


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory) -> Path:
    return write_dataset(tmp_path_factory.mktemp("cic") / "MachineLearningCVE")


@pytest.fixture(scope="session")
def trained_bundle(dataset_dir, tmp_path_factory) -> Path:
    from sentinel_ml.train import run

    root = tmp_path_factory.mktemp("artifacts")
    return run(dataset_dir, root / "models", root / "reports", cap=500)
