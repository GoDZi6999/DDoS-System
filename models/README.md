# Model bundles

Trained models are written here by the Phase 4 pipeline and are **not
committed** (see `.gitignore`). Each bundle is self-contained and versioned:

```
models/<name>/<version>/
  model.pkl             trained estimator
  scaler.pkl            fitted preprocessing (from the shared FeaturePipeline)
  feature_config.json   ordered feature list + definitions
  model_metadata.json   dataset hash, git SHA, params, metrics, library versions
  shap_background.pkl   background sample for SHAP explanations
```

A small demo bundle will be published separately so a fresh clone can run the
demo without training first.
