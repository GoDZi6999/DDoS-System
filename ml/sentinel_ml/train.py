"""End-to-end training: load -> clean -> split -> cross-validate -> fit -> evaluate -> bundle.

Model selection uses blocked cross-validation on the training split only
(best mean macro-F1); the test split is touched once, to report results for
every candidate. Run via `python -m sentinel_ml train`.
"""

import json
import logging
import platform
import subprocess
import time
from datetime import UTC, datetime
from importlib.metadata import version as pkg_version
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from sentinel_ml import data, evaluate, models
from sentinel_ml.bundle import save_bundle
from sentinel_ml.explain import Explainer

logger = logging.getLogger(__name__)

BUNDLE_NAME = "sentinel-flow"
BACKGROUND_ROWS = 200
IMPORTANCE_ROWS = 2000


def _encode(y: pd.Series) -> np.ndarray:
    index = {cls: i for i, cls in enumerate(data.CLASSES)}
    return y.map(index).to_numpy()


def cross_validate(
    name: str, X: pd.DataFrame, y: np.ndarray, folds: np.ndarray, seed: int
) -> list[float]:
    scores = []
    for fold in np.unique(folds):
        train, valid = folds != fold, folds == fold
        pipeline = models.fit(models.CANDIDATES[name](seed), X[train], y[train])
        pred = pipeline.predict(X[valid])
        present = np.unique(y[valid])
        scores.append(float(f1_score(y[valid], pred, labels=present, average="macro")))
        logger.info("  %s fold %d macro-F1 %.4f", name, fold, scores[-1])
    return scores


def _stratified_sample(X: pd.DataFrame, y: np.ndarray, rows: int, seed: int) -> pd.DataFrame:
    per_class = max(rows // len(np.unique(y)), 1)
    rng = np.random.default_rng(seed)
    picked = [
        rng.choice(idx, size=min(per_class, len(idx)), replace=False)
        for idx in (np.flatnonzero(y == c) for c in np.unique(y))
    ]
    return X.iloc[np.sort(np.concatenate(picked))]


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def _next_version(root: Path) -> str:
    base = datetime.now(UTC).strftime("%Y.%m.%d")
    candidate, n = base, 1
    while (root / candidate).exists():
        n += 1
        candidate = f"{base}.{n}"
    return candidate


def run(
    data_dir: Path,
    models_dir: Path,
    reports_dir: Path,
    cap: int = 150_000,
    cv_cap: int = 20_000,
    seed: int = 42,
    candidates: tuple[str, ...] = tuple(models.CANDIDATES),
) -> Path:
    started = time.perf_counter()
    paths = sorted(Path(data_dir).glob("*.csv"))
    logger.info("Loading %d CSV files from %s", len(paths), data_dir)
    raw, files = data.load_cic_csvs(paths)
    dataset = data.prepare(raw)
    del raw
    split = data.temporal_split(dataset)
    logger.info("Cleaned: %s", dataset.report)

    X_train, y_train, folds = data.cap_per_class(
        split.X_train, split.y_train, cap, seed, split.folds
    )
    X_cv, y_cv, folds_cv = data.cap_per_class(X_train, y_train, cv_cap, seed, folds)
    y_train_enc, y_cv_enc, y_test_enc = _encode(y_train), _encode(y_cv), _encode(split.y_test)

    results: dict[str, dict] = {}
    fitted = {}
    for name in candidates:
        logger.info("Cross-validating %s on %d rows", name, len(X_cv))
        cv_scores = cross_validate(name, X_cv, y_cv_enc, folds_cv, seed)
        logger.info("Fitting %s on %d rows", name, len(X_train))
        t0 = time.perf_counter()
        pipeline = models.fit(models.CANDIDATES[name](seed), X_train, y_train_enc)
        fit_seconds = time.perf_counter() - t0
        logger.info("Evaluating %s on %d test rows", name, len(split.X_test))
        metrics = evaluate.evaluate(pipeline, split.X_test, y_test_enc, list(data.CLASSES))
        results[name] = {
            "cv_macro_f1_mean": float(np.mean(cv_scores)),
            "cv_macro_f1_std": float(np.std(cv_scores)),
            "cv_scores": cv_scores,
            "fit_seconds": fit_seconds,
            "test": metrics,
        }
        fitted[name] = pipeline

    selected = max(candidates, key=lambda n: results[n]["cv_macro_f1_mean"])
    pipeline = fitted[selected]
    logger.info("Selected %s by cross-validated macro-F1", selected)

    version = _next_version(models_dir / BUNDLE_NAME)
    background = _stratified_sample(X_train, y_train_enc, BACKGROUND_ROWS, seed)
    explainer = Explainer(pipeline, background)
    importance = explainer.global_importance(
        _stratified_sample(split.X_test, y_test_enc, IMPORTANCE_ROWS, seed)
    )

    metadata = {
        "name": BUNDLE_NAME,
        "version": version,
        "algorithm": selected,
        "params": {k: repr(v) for k, v in pipeline[-1].get_params().items()},
        "trained_at": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "dataset": {
            "name": "CIC-IDS2017 MachineLearningCVE",
            "files": files,
            "sha256": data.file_digest(paths),
            "cleaning": dataset.report,
            "split": "temporal 70/30 per (file, label) group",
            "train_rows": len(split.X_train),
            "train_rows_used": len(X_train),
            "test_rows": len(split.X_test),
            "train_cap_per_class": cap,
            "train_class_counts": y_train.value_counts().to_dict(),
            "test_class_counts": split.y_test.value_counts().to_dict(),
        },
        "selection": "highest mean macro-F1 over 5 blocked CV folds of the training split",
        "candidates": {
            n: {k: v for k, v in r.items() if k != "test"}
            | {"test_macro_f1": r["test"]["macro_f1"]}
            for n, r in results.items()
        },
        "metrics": results[selected]["test"],
        "top_features": importance.head(10).round(4).to_dict(),
        "environment": {
            "python": platform.python_version(),
            **{p: pkg_version(p) for p in ("scikit-learn", "xgboost", "shap", "pandas", "numpy")},
        },
    }
    bundle_dir = save_bundle(
        models_dir / BUNDLE_NAME / version, pipeline, list(data.CLASSES), background, metadata
    )

    report_dir = reports_dir / version
    report_dir.mkdir(parents=True, exist_ok=True)
    evaluate.plot_confusion_matrix(
        results[selected]["test"]["confusion_matrix"],
        list(data.CLASSES),
        report_dir / "confusion_matrix.png",
    )
    evaluate.plot_importance(importance, report_dir / "feature_importance.png")
    (report_dir / "metrics.json").write_text(
        json.dumps(
            {"selected": selected, "results": results, "dataset": metadata["dataset"]},
            indent=2,
            default=str,
        )
    )
    (report_dir / "report.md").write_text(
        render_report(metadata, results, selected, importance, time.perf_counter() - started)
    )
    logger.info("Bundle: %s  Report: %s", bundle_dir, report_dir / "report.md")
    return bundle_dir


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def render_report(
    metadata: dict, results: dict, selected: str, importance: pd.Series, seconds: float
) -> str:
    ds = metadata["dataset"]
    clean = ds["cleaning"]
    test = results[selected]["test"]
    lines = [
        f"# Model report — {metadata['name']} {metadata['version']}",
        "",
        f"Selected model: **{selected}** (by cross-validated macro-F1). "
        f"Trained {metadata['trained_at'][:19]} UTC in {seconds / 60:.1f} min, "
        f"commit `{(metadata['git_commit'] or 'unknown')[:10]}`.",
        "",
        "## Data",
        "",
        f"CIC-IDS2017 MachineLearningCVE, {len(ds['files'])} files "
        f"(sha256 `{ds['sha256'][:16]}…`).",
        "",
        "| Step | Rows |",
        "|---|---:|",
        f"| Loaded | {clean['rows_loaded']:,} |",
        f"| Dropped: classes too rare to learn (Infiltration, Heartbleed) | {clean['dropped_rare_classes']:,} |",
        f"| Dropped: negative flow duration (CICFlowMeter bug) | {clean['dropped_negative_duration']:,} |",
        f"| Dropped: exact duplicates | {clean['dropped_exact_duplicates']:,} |",
        f"| Dropped: identical features with conflicting labels | {clean['dropped_conflicting_labels']:,} |",
        f"| **Kept** | **{clean['rows_kept']:,}** |",
        "",
        f"Split: {ds['split']} — the later part of every attack run is held out, "
        "so near-identical consecutive flows cannot leak from training into test. "
        f"Training used at most {ds['train_cap_per_class']:,} rows per class "
        f"({ds['train_rows_used']:,} of {ds['train_rows']:,}); the test set is used in full.",
        "",
        "| Class | Train (used) | Test |",
        "|---|---:|---:|",
    ]
    for cls in test["per_class"]:
        lines.append(
            f"| {cls} | {ds['train_class_counts'].get(cls, 0):,} | {ds['test_class_counts'].get(cls, 0):,} |"
        )
    lines += [
        "",
        "## Model comparison",
        "",
        "| Model | CV macro-F1 | Test macro-F1 | Test accuracy | ROC-AUC (OvR) | PR-AUC | "
        "Attack detection | False positives | Latency (1 flow) | Fit |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, r in results.items():
        t = r["test"]
        mark = " ✅" if name == selected else ""
        lines.append(
            f"| {name}{mark} | {r['cv_macro_f1_mean']:.4f} ± {r['cv_macro_f1_std']:.4f} | "
            f"{t['macro_f1']:.4f} | {_pct(t['accuracy'])} | {t['roc_auc_ovr_macro']:.4f} | "
            f"{t['pr_auc_macro']:.4f} | {_pct(t['attack_detection_rate'])} | "
            f"{_pct(t['false_positive_rate'])} | {t['single_flow_ms']:.2f} ms | {r['fit_seconds']:.0f} s |"
        )
    lines += [
        "",
        "*Attack detection*: share of attack flows flagged as any attack. "
        "*False positives*: share of benign flows flagged as an attack.",
        "",
        f"## Per-class results ({selected}, test set)",
        "",
        "| Class | Precision | Recall | F1 | Support |",
        "|---|---:|---:|---:|---:|",
    ]
    for cls, m in test["per_class"].items():
        lines.append(
            f"| {cls} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['support']:,} |"
        )
    lines += [
        "",
        "![Confusion matrix](confusion_matrix.png)",
        "",
        "## What drives the predictions",
        "",
        "Mean absolute SHAP value per feature on a stratified test sample:",
        "",
        "| Feature | Mean \\|SHAP\\| |",
        "|---|---:|",
    ]
    for feature, value in importance.head(10).items():
        lines.append(f"| `{feature}` | {value:.4f} |")
    lines += [
        "",
        "![Feature importance](feature_importance.png)",
        "",
        "## Caveats",
        "",
        "- One dataset, one capture environment: these numbers measure how well the model "
        "separates CIC-IDS2017's traffic, not how it will do on another network. "
        "Expect lower scores on live traffic until it is validated there.",
        "- CIC-IDS2017 has documented labelling and flow-construction errors "
        "(Engelen et al., 2021).",
        "- Cross-validation runs on class-capped (balanced) data while the test set keeps the "
        "real mix (mostly benign), so rare-class precision is lower on test: even a 0.1% "
        "false-positive rate on hundreds of thousands of benign flows outnumbers a few hundred "
        "attack flows. The test numbers are the realistic ones.",
        "- Port scans and botnet traffic are poorly separated per flow: deduplication shows most "
        "scan probes are feature-identical to each other and close to short benign flows. They "
        "are patterns across flows (one source, many ports or hosts), which needs the "
        "window-level features planned for the real-time engine (Phase 5).",
        "- TCP initial window sizes rank highest; they partly reflect the operating systems in "
        "the CIC testbed and may not transfer to other networks (an ablation without them is a "
        "planned check).",
        "- Rare classes (botnet, web attacks) have few test flows, so their scores are noisy.",
        "- Port numbers are deliberately not used as features, to stop the model learning "
        '"port 80 = attack" shortcuts specific to this dataset.',
        "- SHAP explains the model's reasoning, not ground-truth causality.",
        "",
    ]
    return "\n".join(lines)
