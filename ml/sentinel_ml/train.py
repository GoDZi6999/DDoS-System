"""End-to-end training: load -> clean -> split -> validate -> tune -> fit -> evaluate -> bundle.

Selection uses a validation set carved from the training split: the last 20%
(capture order) of every (file, label) group's training part, at the real
class mix. Every candidate is fitted on the rest and scored there; the best is
refitted on the whole training split and bundled. The test split is only used
to report results.

Decision weights (decision.py) are opt-in (tune_decisions=True): in the
2026.10.04 run, weights tuned on the validation-stage model made the refitted
model worse on test (macro-F1 0.817 vs 0.853 with argmax), because refitting
on the latest part of each run shifts its probabilities. Without a held-out
set for the refitted model they cannot be tuned reliably, so bundles decide
by argmax unless asked otherwise.

When the reference bundle (gate.REFERENCE_VERSION) is present, the shipped
model is checked against the release gate and the verdict is recorded in the
metadata and the report.
Run via `python -m sentinel_ml train`.
"""

import json
import logging
import os
import platform
import subprocess
import time
from datetime import UTC, datetime
from importlib.metadata import version as pkg_version
from pathlib import Path

import numpy as np
import pandas as pd

from sentinel_ml import data, evaluate, gate, models
from sentinel_ml.bundle import save_bundle
from sentinel_ml.decision import decide, macro_f1, tune_weights
from sentinel_ml.explain import Explainer

logger = logging.getLogger(__name__)

BUNDLE_NAME = "sentinel-flow"
BACKGROUND_ROWS = 200
IMPORTANCE_ROWS = 2000
VALIDATION_FOLD = 4  # temporal_split's folds 0-4: the last fifth of each training run
ABLATION_FEATURES = ("init_win_bytes_fwd", "init_win_bytes_bwd")


def _encode(y: pd.Series) -> np.ndarray:
    index = {cls: i for i, cls in enumerate(data.CLASSES)}
    return y.map(index).to_numpy()


def validate(
    pipeline, X_fit: pd.DataFrame, y_fit: np.ndarray, X_val: pd.DataFrame, y_val: np.ndarray
) -> tuple[object, dict]:
    """Fit on the fit part, score on validation, tune decision weights."""
    t0 = time.perf_counter()
    fitted = models.fit(pipeline, X_fit, y_fit)
    proba = fitted.predict_proba(X_val)
    weights = tune_weights(proba, y_val)
    return fitted, {
        "val_macro_f1_argmax": macro_f1(y_val, decide(proba)),
        "val_macro_f1": macro_f1(y_val, decide(proba, weights)),
        "weights": weights,
        "fit_seconds": time.perf_counter() - t0,
    }


def _stratified_sample(X: pd.DataFrame, y: np.ndarray, rows: int, seed: int) -> pd.DataFrame:
    per_class = max(rows // len(np.unique(y)), 1)
    rng = np.random.default_rng(seed)
    picked = [
        rng.choice(idx, size=min(per_class, len(idx)), replace=False)
        for idx in (np.flatnonzero(y == c) for c in np.unique(y))
    ]
    return X.iloc[np.sort(np.concatenate(picked))]


def _git_commit() -> str | None:
    if os.environ.get("GIT_COMMIT"):  # e.g. training in a container without the .git directory
        return os.environ["GIT_COMMIT"]
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
    seed: int = 42,
    candidates: tuple[str, ...] = tuple(models.CANDIDATES),
    ablation: bool = True,
    tune_decisions: bool = False,
) -> Path:
    started = time.perf_counter()
    paths = sorted(Path(data_dir).glob("*.csv"))
    logger.info("Loading %d CSV files from %s", len(paths), data_dir)
    raw, files = data.load_cic_csvs(paths)
    dataset = data.prepare(raw)
    del raw
    split = data.temporal_split(dataset)
    logger.info("Cleaned: %s", dataset.report)

    # Benign is kept in full so the model learns realistic base rates; attack
    # classes are capped only to bound training time.
    X_train, y_train, folds = data.cap_per_class(
        split.X_train, split.y_train, cap, seed, split.folds, uncapped=(data.CLASSES[0],)
    )
    y_train_enc, y_test_enc = _encode(y_train), _encode(split.y_test)
    fit_part = folds != VALIDATION_FOLD
    X_fit, y_fit = X_train[fit_part], y_train_enc[fit_part]
    X_val, y_val = X_train[~fit_part], y_train_enc[~fit_part]
    logger.info("Fit on %d rows, validate on %d (real class mix)", len(X_fit), len(X_val))

    results: dict[str, dict] = {}
    for name in candidates:
        logger.info("Validating %s", name)
        fitted, outcome = validate(models.CANDIDATES[name](seed), X_fit, y_fit, X_val, y_val)
        outcome["test"] = evaluate.evaluate(
            fitted, split.X_test, y_test_enc, list(data.CLASSES), outcome["weights"]
        )
        logger.info(
            "  %s validation macro-F1 %.4f (argmax %.4f), test %.4f",
            name,
            outcome["val_macro_f1"],
            outcome["val_macro_f1_argmax"],
            outcome["test"]["macro_f1"],
        )
        results[name] = outcome

    score = "val_macro_f1" if tune_decisions else "val_macro_f1_argmax"
    selected = max(candidates, key=lambda n: results[n][score])
    weights = results[selected]["weights"] if tune_decisions else np.ones(len(data.CLASSES))
    logger.info("Selected %s; refitting on all %d training rows", selected, len(X_train))
    t0 = time.perf_counter()
    pipeline = models.fit(models.CANDIDATES[selected](seed), X_train, y_train_enc)
    fit_seconds = time.perf_counter() - t0
    final = evaluate.evaluate(pipeline, split.X_test, y_test_enc, list(data.CLASSES), weights)
    final_argmax = evaluate.evaluate(pipeline, split.X_test, y_test_enc, list(data.CLASSES))
    logger.info(
        "Shipped model: test macro-F1 %.4f with decision weights, %.4f with argmax",
        final["macro_f1"],
        final_argmax["macro_f1"],
    )

    reference = gate.reference_metrics(models_dir)
    gate_result = None if reference is None else gate.check(final, reference)
    if gate_result is not None:
        logger.info(
            "Release gate vs %s: %s",
            gate_result["reference"],
            "PASSED" if gate_result["passed"] else "FAILED",
        )

    ablation_result = None
    if ablation:
        logger.info("Ablation: %s without %s", selected, ", ".join(ABLATION_FEATURES))
        variant = models.without_features(models.CANDIDATES[selected](seed), ABLATION_FEATURES)
        fitted, outcome = validate(variant, X_fit, y_fit, X_val, y_val)
        outcome["test"] = evaluate.evaluate(
            fitted, split.X_test, y_test_enc, list(data.CLASSES), outcome["weights"]
        )
        ablation_result = {"dropped": list(ABLATION_FEATURES), **outcome}

    version = _next_version(models_dir / BUNDLE_NAME)
    background = _stratified_sample(X_train, y_train_enc, BACKGROUND_ROWS, seed)
    explainer = Explainer(pipeline, background)
    importance = explainer.global_importance(
        _stratified_sample(split.X_test, y_test_enc, IMPORTANCE_ROWS, seed)
    )

    def summary(outcome: dict) -> dict:
        return {
            "val_macro_f1": outcome["val_macro_f1"],
            "val_macro_f1_argmax": outcome["val_macro_f1_argmax"],
            "test_macro_f1": outcome["test"]["macro_f1"],
            "fit_seconds": outcome["fit_seconds"],
            "decision_weights": dict(
                zip(data.CLASSES, outcome["weights"].round(4).tolist(), strict=True)
            ),
        }

    metadata = {
        "name": BUNDLE_NAME,
        "version": version,
        "algorithm": selected,
        "params": {k: repr(v) for k, v in pipeline[-1].get_params().items()},
        "decision_weights": dict(zip(data.CLASSES, weights.round(4).tolist(), strict=True)),
        "trained_at": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "dataset": {
            "name": "CIC-IDS2017 MachineLearningCVE",
            "files": files,
            "sha256": data.file_digest(paths),
            "cleaning": dataset.report,
            "split": "temporal 70/30 per (file, label) group",
            "validation": "last 20% of each group's training part, real class mix",
            "train_rows": len(split.X_train),
            "train_rows_used": len(X_train),
            "validation_rows": len(X_val),
            "test_rows": len(split.X_test),
            "train_cap_per_attack_class": cap,
            "train_class_counts": y_train.value_counts().to_dict(),
            "test_class_counts": split.y_test.value_counts().to_dict(),
        },
        "selection": "highest validation macro-F1"
        + (" after decision-weight tuning" if tune_decisions else " (argmax)"),
        "decision_tuning": tune_decisions,
        "candidates": {n: summary(r) for n, r in results.items()},
        "ablation": None
        if ablation_result is None
        else {"dropped": ablation_result["dropped"], **summary(ablation_result)},
        "metrics": final,
        "release_gate": gate_result,
        "metrics_argmax": {k: v for k, v in final_argmax.items() if k != "confusion_matrix"},
        "fit_seconds": fit_seconds,
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
        final["confusion_matrix"], list(data.CLASSES), report_dir / "confusion_matrix.png"
    )
    evaluate.plot_importance(importance, report_dir / "feature_importance.png")
    (report_dir / "metrics.json").write_text(
        json.dumps(
            {
                "selected": selected,
                "shipped": final,
                "shipped_argmax": final_argmax,
                "candidates": results,
                "ablation": ablation_result,
                "release_gate": gate_result,
                "dataset": metadata["dataset"],
            },
            indent=2,
            default=lambda o: o.tolist() if isinstance(o, np.ndarray) else str(o),
        )
    )
    (report_dir / "report.md").write_text(
        render_report(
            metadata,
            results,
            selected,
            final,
            final_argmax,
            ablation_result,
            importance,
            time.perf_counter() - started,
        )
    )
    logger.info("Bundle: %s  Report: %s", bundle_dir, report_dir / "report.md")
    return bundle_dir


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _gate_section(result: dict | None) -> list[str]:
    if result is None:
        return []
    lines = [
        f"## Release gate vs {result['reference']}: "
        f"{'**passed**' if result['passed'] else '**failed**'}",
        "",
        "Fixed before evaluation (`sentinel_ml/gate.py`): strictly fewer false positives, and "
        f"no class losing more than {result['max_recall_drop'] * 100:.0f} points of recall.",
        "",
        "| Check | This model | Reference | Result |",
        "|---|---:|---:|---|",
    ]
    for c in result["checks"]:
        fmt = _pct if c["name"] == "false_positive_rate" else (lambda v: f"{v:.4f}")
        lines.append(
            f"| {c['name']} | {fmt(c['candidate'])} | {fmt(c['reference'])} | "
            f"{'pass' if c['passed'] else 'FAIL'} |"
        )
    return [*lines, ""]


def render_report(
    metadata: dict,
    results: dict,
    selected: str,
    final: dict,
    final_argmax: dict,
    ablation: dict | None,
    importance: pd.Series,
    seconds: float,
) -> str:
    ds = metadata["dataset"]
    clean = ds["cleaning"]
    lines = [
        f"# Model report — {metadata['name']} {metadata['version']}",
        "",
        f"Selected model: **{selected}** ({metadata['selection']}). "
        f"Trained {metadata['trained_at'][:19]} UTC in {seconds / 60:.1f} min, "
        f"commit `{(metadata['git_commit'] or 'unknown')[:10]}`.",
        "",
        "## Headline (test set, shipped model)",
        "",
        "| | Macro-F1 | Accuracy | Attack detection | False positives | Calibration error |",
        "|---|---:|---:|---:|---:|---:|",
        f"| {'With tuned decision weights (shipped)' if metadata['decision_tuning'] else 'Shipped (argmax)'} | {final['macro_f1']:.4f} | "
        f"{_pct(final['accuracy'])} | {_pct(final['attack_detection_rate'])} | "
        f"{_pct(final['false_positive_rate'])} | {final['calibration_error']:.4f} |",
        *(
            [
                f"| Plain argmax | {final_argmax['macro_f1']:.4f} | "
                f"{_pct(final_argmax['accuracy'])} | "
                f"{_pct(final_argmax['attack_detection_rate'])} | "
                f"{_pct(final_argmax['false_positive_rate'])} | "
                f"{final_argmax['calibration_error']:.4f} |"
            ]
            if metadata["decision_tuning"]
            else []
        ),
        "",
        "*Attack detection*: share of attack flows flagged as any attack. *False positives*: "
        "share of benign flows flagged as an attack. *Calibration error*: expected calibration "
        "error of the reported confidence (0 = confidence matches accuracy).",
        "",
        *_gate_section(metadata.get("release_gate")),
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
        f"Split: {ds['split']}: the later part of every attack run is held out, so "
        "near-identical consecutive flows cannot leak into the test set. Validation: "
        f"{ds['validation']} ({ds['validation_rows']:,} rows). Training kept every benign flow "
        f"and at most {ds['train_cap_per_attack_class']:,} flows per attack class "
        f"({ds['train_rows_used']:,} of {ds['train_rows']:,}); the test set is used in full.",
        "",
        "| Class | Train (used) | Test |",
        "|---|---:|---:|",
    ]
    for cls in final["per_class"]:
        lines.append(
            f"| {cls} | {ds['train_class_counts'].get(cls, 0):,} | {ds['test_class_counts'].get(cls, 0):,} |"
        )
    lines += [
        "",
        "## Model comparison",
        "",
        "Each candidate is fitted without the validation part, scored on it, and gets its own "
        "decision weights. Test scores in this table come from these validation-stage models; "
        "the shipped model is the selected candidate refitted on the whole training split.",
        "",
        "| Model | Validation macro-F1 (argmax → tuned) | Test macro-F1 | ROC-AUC (OvR) | PR-AUC | "
        "Attack detection | False positives | Latency (1 flow) | Fit |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, r in results.items():
        t = r["test"]
        mark = " ✅" if name == selected else ""
        lines.append(
            f"| {name}{mark} | {r['val_macro_f1_argmax']:.4f} → {r['val_macro_f1']:.4f} | "
            f"{t['macro_f1']:.4f} | {t['roc_auc_ovr_macro']:.4f} | {t['pr_auc_macro']:.4f} | "
            f"{_pct(t['attack_detection_rate'])} | {_pct(t['false_positive_rate'])} | "
            f"{t['single_flow_ms']:.2f} ms | {r['fit_seconds']:.0f} s |"
        )
    lines += [
        "",
        f"## Per-class results ({selected}, shipped, test set)",
        "",
        "| Class | Precision | Recall | F1 | Support | Decision weight |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cls, m in final["per_class"].items():
        lines.append(
            f"| {cls} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['support']:,} | {metadata['decision_weights'][cls]:.3f} |"
        )
    lines += [
        "",
        "A decision weight below 1 makes the model more conservative about that class: the "
        "label is argmax(probability x weight), so a class with weight 0.1 must be about ten "
        "times more likely than benign before it is reported.",
        "",
        "![Confusion matrix](confusion_matrix.png)",
        "",
    ]
    if ablation is not None:
        t = ablation["test"]
        lines += [
            "## Ablation: without TCP initial window sizes",
            "",
            f"Same model and procedure without `{'`, `'.join(ablation['dropped'])}`, which rank "
            "high and partly reflect the testbed's operating systems.",
            "",
            "| Variant | Validation macro-F1 (argmax → tuned) | Test macro-F1 | False positives |",
            "|---|---:|---:|---:|",
            f"| All features (validation-stage) | {results[selected]['val_macro_f1_argmax']:.4f} → "
            f"{results[selected]['val_macro_f1']:.4f} | {results[selected]['test']['macro_f1']:.4f} | "
            f"{_pct(results[selected]['test']['false_positive_rate'])} |",
            f"| Without window sizes | {ablation['val_macro_f1_argmax']:.4f} → "
            f"{ablation['val_macro_f1']:.4f} | {t['macro_f1']:.4f} | {_pct(t['false_positive_rate'])} |",
            "",
        ]
    lines += [
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
        "separates CIC-IDS2017's traffic, not how it will do on another network.",
        "- CIC-IDS2017 has documented labelling and flow-construction errors "
        "(Engelen et al., 2021).",
        "- Validation and test come from different parts of each attack run; where an attack "
        "changes over its run (port scans most of all), validation scores are optimistic and "
        "the test scores are the realistic ones.",
        "- Port scans and botnet traffic are poorly separated per flow; the real-time engine "
        "adds a window rule for scans.",
        '- Port numbers are deliberately not features, to avoid "port 80 = attack" shortcuts.',
        "- SHAP explains the model's reasoning, not ground-truth causality.",
        "",
    ]
    return "\n".join(lines)
