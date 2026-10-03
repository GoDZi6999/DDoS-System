# Model bundles

Written by `python -m sentinel_ml train` (see [`ml/README.md`](../ml/README.md)).
Each bundle is self-contained and versioned:

```
models/sentinel-flow/<version>/
  model.joblib          fitted Pipeline: shared feature preprocessing + estimator
  background.joblib     200 training flows used as the SHAP background
  feature_config.json   ordered feature list (names, descriptions, CIC columns), classes
  model_metadata.json   dataset digest, cleaning counts, split, params, metrics,
                        library versions, git commit, SHA-256 of the joblib files
```

The current bundle, **`sentinel-flow/2026.10.03`** (XGBoost, ~2 MB), is
committed so a fresh clone can run inference without downloading the dataset.
Its evaluation report is in [`ml/reports/2026.10.03/`](../ml/reports/2026.10.03/report.md).
Other bundles are git-ignored.

`.joblib` files are pickles, and loading one executes code. `load_bundle`
verifies the recorded checksums and the feature list before loading, but only
load bundles you built or trust.
