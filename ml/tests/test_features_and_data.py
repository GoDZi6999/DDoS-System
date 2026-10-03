import numpy as np
import pandas as pd
import pytest

from sentinel_ml import data, features
from sentinel_ml.features import FEATURE_NAMES, FEATURES


def _cic_row(**overrides) -> pd.DataFrame:
    row = {f.cic_column: 10.0 for f in FEATURES if f.cic_column}
    row.update({"Flow Duration": 2_000_000, "Total Fwd Packets": 6, "Total Backward Packets": 4})
    row.update({"Total Length of Fwd Packets": 600, "Total Length of Bwd Packets": 400})
    row.update(overrides)
    return pd.DataFrame([row])


def test_cic_columns_are_converted_to_canonical_units():
    frame = features.from_cic(_cic_row())

    assert list(frame.columns) == list(FEATURE_NAMES)
    assert frame.loc[0, "flow_duration_s"] == 2.0  # microseconds -> seconds
    assert frame.loc[0, "flow_iat_mean"] == pytest.approx(10e-6)
    assert frame.loc[0, "flow_bytes_per_s"] == 500.0  # (600 + 400) / 2 s
    assert frame.loc[0, "flow_packets_per_s"] == 5.0


def test_zero_duration_gives_zero_rates_not_infinity():
    frame = features.from_cic(_cic_row(**{"Flow Duration": 0, "Flow IAT Std": np.nan}))

    assert frame.loc[0, "flow_bytes_per_s"] == 0.0
    assert np.isfinite(frame.to_numpy()).all()


def test_live_records_and_offline_rows_produce_identical_vectors():
    offline = features.from_cic(_cic_row())
    record = offline.iloc[0].to_dict() | {"flow_bytes_per_s": 123456.0, "src_ip": "10.0.0.1"}

    live = features.from_records([record])

    pd.testing.assert_frame_equal(live, offline)


def test_live_records_missing_a_feature_are_rejected():
    record = features.from_cic(_cic_row()).iloc[0].drop("syn_flag_count").to_dict()

    with pytest.raises(ValueError, match="syn_flag_count"):
        features.from_records([record])


def test_labels_normalise_including_the_misencoded_dash():
    assert data.normalise_label("Web Attack � Brute Force") == "web attack brute force"
    assert data.normalise_label("Web Attack ï¿½ XSS") == "web attack xss"
    assert data.normalise_label(" DoS Slowhttptest ") == "dos slowhttptest"


def test_prepare_cleans_and_reports(dataset_dir):
    raw, files = data.load_cic_csvs(sorted(dataset_dir.glob("*.csv")))
    dataset = data.prepare(raw)

    assert len(files) == 3
    assert dataset.report["dropped_rare_classes"] == 5
    assert dataset.report["dropped_negative_duration"] == 3
    assert dataset.report["dropped_exact_duplicates"] == 6
    assert set(dataset.labels) == set(data.CLASSES)
    assert dataset.report["class_counts"]["webattack"] == 100
    assert not dataset.features.duplicated().any()


def test_unknown_labels_fail_loudly():
    raw = _cic_row().assign(Label="Something New", source_file="x.csv")

    with pytest.raises(ValueError, match="unmapped labels"):
        data.prepare(raw)


def test_temporal_split_holds_out_the_end_of_every_group(dataset_dir):
    raw, _ = data.load_cic_csvs(sorted(dataset_dir.glob("*.csv")))
    dataset = data.prepare(raw)

    split = data.temporal_split(dataset)

    assert len(split.X_train) + len(split.X_test) == len(dataset.features)
    for label in data.CLASSES:  # every class appears on both sides
        assert (split.y_train == label).any() and (split.y_test == label).any()
    assert set(np.unique(split.folds)) == {0, 1, 2, 3, 4}
    assert 0.65 < len(split.X_train) / len(dataset.features) < 0.72
    # The first DDoS flow is in training, the last one in test.
    ddos = dataset.features[dataset.labels == "ddos"]
    assert (split.X_train == ddos.iloc[0]).all(axis=1).any()
    assert (split.X_test == ddos.iloc[-1]).all(axis=1).any()


def test_cap_per_class_limits_rows():
    X = pd.DataFrame({"a": range(10)})
    y = pd.Series(["x"] * 8 + ["y"] * 2)

    _, y_capped, _ = data.cap_per_class(X, y, cap=3, seed=0)

    assert y_capped.value_counts().to_dict() == {"x": 3, "y": 2}
