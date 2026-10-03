"""Export a small sample of real CIC-IDS2017 flows (features + label) for the
real-time engine's demo simulator.

Rows come from the held-out *test* split only, so a demo never shows the
model flows it was trained on. The file has no IPs or timestamps; the
simulator assigns those (from documentation address ranges).
"""

from pathlib import Path

import pandas as pd

from sentinel_ml import data

DEFAULT_PER_CLASS = {"benign": 2000}
PER_CLASS = 300


def export_profiles(data_dir: Path, out: Path, seed: int = 7) -> pd.DataFrame:
    raw, _ = data.load_cic_csvs(sorted(Path(data_dir).glob("*.csv")))
    split = data.temporal_split(data.prepare(raw))
    frames = []
    for label in data.CLASSES:
        rows = split.X_test[split.y_test == label]
        n = min(DEFAULT_PER_CLASS.get(label, PER_CLASS), len(rows))
        frames.append(rows.sample(n=n, random_state=seed).assign(label=label))
    profiles = pd.concat(frames, ignore_index=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    profiles.to_csv(out, index=False, float_format="%.6g")
    return profiles
