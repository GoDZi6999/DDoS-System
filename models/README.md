# Model bundles

Written by `python -m argus_ml train` (see [`ml/README.md`](../ml/README.md)).
Each bundle is self-contained and versioned:

```
models/argus-flow/<version>/
  model.joblib          fitted Pipeline: shared feature preprocessing + estimator
  background.joblib     200 training flows used as the SHAP background
  feature_config.json   ordered feature list (names, descriptions, CIC columns), classes
  model_metadata.json   dataset digest, cleaning counts, split, params, metrics,
                        library versions, git commit, SHA-256 of the joblib files
```

Two bundles are committed, so a fresh clone can run inference without
downloading the dataset (other bundles are git-ignored):

| Bundle | Role | Test macro-F1 | False positives | Botnet recall | Report |
|---|---|---:|---:|---:|---|
| `argus-flow/2026.10.03` | **default** | 0.828 | 0.20% | 0.92 | [report](../ml/reports/2026.10.03/report.md) |
| `argus-flow/2026.10.04` | opt-in candidate | **0.853** | **0.11%** | 0.75 | [report](../ml/reports/2026.10.04/report.md) |

The candidate is better on most measures (45% fewer false positives, higher
precision on every rare class, better calibration) but did not pass the
release gate set before it was evaluated: no class may lose more than 10
points of recall, and botnet recall fell by 17. Choose it with
`MODEL_BUNDLE=models/argus-flow/2026.10.04` in `.env` if false alarms
matter more to you than botnet sensitivity. See
[`docs/ML_METHODOLOGY.md`](../docs/ML_METHODOLOGY.md#8-model-iteration-20261004).

`.joblib` files are pickles, and loading one executes code. `load_bundle`
verifies the recorded checksums and the feature list before loading, but only
load bundles you built or trust.
