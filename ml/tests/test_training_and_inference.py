import json
import shutil

import pytest

from sentinel_ml import bundle, data, features, models
from sentinel_ml.__main__ import main
from sentinel_ml.explain import Explainer
from sentinel_ml.inference import Predictor


def test_training_writes_a_complete_bundle_and_report(trained_bundle):
    files = {p.name for p in trained_bundle.iterdir()}
    metadata = json.loads((trained_bundle / bundle.METADATA_FILE).read_text())
    report_dir = trained_bundle.parents[2] / "reports" / metadata["version"]

    assert files == {
        "model.joblib",
        "background.joblib",
        "feature_config.json",
        "model_metadata.json",
    }
    assert metadata["algorithm"] in {"logistic_regression", "random_forest", "xgboost"}
    assert set(metadata["candidates"]) == {"logistic_regression", "random_forest", "xgboost"}
    assert metadata["dataset"]["cleaning"]["dropped_exact_duplicates"] == 6
    assert len(metadata["candidates"]["xgboost"]["cv_scores"]) == 5
    # Synthetic classes are well separated, so every candidate should learn them.
    assert metadata["metrics"]["macro_f1"] > 0.9
    assert {"confusion_matrix.png", "feature_importance.png", "metrics.json", "report.md"} <= {
        p.name for p in report_dir.iterdir()
    }
    assert "Model comparison" in (report_dir / "report.md").read_text()


def test_predictor_labels_and_explains_attacks(trained_bundle, dataset_dir):
    raw, _ = data.load_cic_csvs(sorted(dataset_dir.glob("*.csv")))
    dataset = data.prepare(raw)
    sample = dataset.features.groupby(dataset.labels).head(3)

    predictions = Predictor.from_bundle(trained_bundle).predict(sample)

    assert len(predictions) == len(sample)
    attack = next(p for p in predictions if p.is_attack)
    assert attack.summary().startswith(f"{attack.label} detected — confidence ")
    assert 0 < len(attack.explanation) <= 5
    item = attack.explanation[0]
    assert item["feature"] in features.FEATURE_NAMES
    assert item["contribution"] > 0 and 0 < item["weight"] <= 100
    assert abs(sum(attack.class_probs.values()) - 1) < 1e-3
    benign = next(p for p in predictions if not p.is_attack)
    assert benign.explanation == []  # explained on demand only


def test_offline_and_live_inputs_give_the_same_prediction(trained_bundle, dataset_dir):
    raw, _ = data.load_cic_csvs(sorted(dataset_dir.glob("*.csv")))
    offline = data.prepare(raw).features.head(20)
    live = features.from_records(offline.to_dict(orient="records"))
    predictor = Predictor.from_bundle(trained_bundle)

    a = predictor.predict(offline, explain="none")
    b = predictor.predict(live, explain="none")

    assert [(p.label, p.confidence) for p in a] == [(p.label, p.confidence) for p in b]


def test_tampered_bundle_is_refused(trained_bundle, tmp_path):
    copy = shutil.copytree(trained_bundle, tmp_path / "bundle")
    with (copy / bundle.MODEL_FILE).open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(bundle.BundleError, match="checksum"):
        bundle.load_bundle(copy)


def test_bundle_with_other_features_is_refused(trained_bundle, tmp_path):
    copy = shutil.copytree(trained_bundle, tmp_path / "bundle")
    config = json.loads((copy / bundle.FEATURES_FILE).read_text())
    config["features"] = config["features"][:-1]
    (copy / bundle.FEATURES_FILE).write_text(json.dumps(config))

    with pytest.raises(bundle.BundleError, match="different feature definition"):
        bundle.load_bundle(copy)


def test_predict_command(trained_bundle, dataset_dir, capsys):
    csv = sorted(dataset_dir.glob("*.csv"))[0]

    assert (
        main(["predict", "--bundle", str(trained_bundle), "--csv", str(csv), "--limit", "3"]) == 0
    )

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 3
    assert {"summary", "label", "confidence", "class_probs", "explanation"} <= set(
        json.loads(lines[0])
    )


@pytest.mark.parametrize("name", list(models.CANDIDATES))
def test_every_candidate_can_be_explained(name, dataset_dir):
    raw, _ = data.load_cic_csvs(sorted(dataset_dir.glob("*.csv")))
    dataset = data.prepare(raw)
    y = dataset.labels.map({c: i for i, c in enumerate(data.CLASSES)}).to_numpy()
    pipeline = models.fit(models.CANDIDATES[name](0), dataset.features, y)
    explainer = Explainer(pipeline, dataset.features.head(50))

    importance = explainer.global_importance(dataset.features.head(20))
    explanations = explainer.explain(dataset.features.head(3), y[:3])

    assert importance.index[0] in features.FEATURE_NAMES
    assert len(explanations) == 3
