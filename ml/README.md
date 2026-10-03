# ML pipeline (Phase 4)

Offline training and evaluation, plus the inference code used by the
real-time ML engine. Methodology: [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §3.

```
sentinel_features/   flow -> feature vector; the ONLY feature code, imported by
                     both training and live inference (prevents train/serve skew)
training/            dataset cleaning, label mapping, LR / RF / XGBoost, CV
evaluation/          confusion matrix, precision/recall/F1, ROC-AUC, PR-AUC,
                     cross-dataset results, feature importance
inference/           load a model bundle, predict, SHAP top-k explanation
notebooks/           exploration only; nothing here is imported by services
```

Every trained model is saved as a versioned bundle in `models/<name>/<version>/`
(`model.pkl`, `scaler.pkl`, `feature_config.json`, `model_metadata.json`,
`shap_background.pkl`). See [`models/README.md`](../models/README.md).
