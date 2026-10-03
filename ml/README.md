# ML pipeline (`sentinel_ml`)

Training, evaluation and inference for SentinelAI's flow classifier.
Methodology and results: [`docs/ML_METHODOLOGY.md`](../docs/ML_METHODOLOGY.md);
latest report: [`ml/reports/`](reports/).

```
sentinel_ml/
  features.py    THE feature definition (37 flow statistics, canonical units),
                 shared by training (from_cic) and live inference (from_records)
  data.py        load CIC-IDS2017, map labels, clean, deduplicate, temporal split
  models.py      candidates: logistic regression (baseline), random forest, XGBoost;
                 each a Pipeline that starts with the shared FlowPreprocessor
  train.py       CV -> fit -> evaluate -> bundle -> report
  evaluate.py    metrics (per-class P/R/F1, macro-F1, ROC-AUC, PR-AUC, detection
                 rate, false-positive rate, latency) and plots
  explain.py     SHAP explanations per prediction and global importance
  bundle.py      versioned, checksum-verified model bundles
  inference.py   Predictor: label + confidence + class probabilities + explanation
```

## Train

Needs the CIC-IDS2017 CSVs in `data/raw/cic-ids2017/MachineLearningCVE/`
(see [`data/README.md`](../data/README.md)), Python 3.12 and ~8 GB RAM.
About 20 minutes on 4 cores.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r ml/requirements.txt
PYTHONPATH=ml python -m sentinel_ml train          # from the repo root
```

Output:

- `models/sentinel-flow/<version>/`: `model.joblib`, `background.joblib`,
  `feature_config.json`, `model_metadata.json` (not committed; large).
- `ml/reports/<version>/`: `report.md`, `metrics.json`, confusion matrix and
  feature-importance plots (committed as evidence).

Preprocessing lives inside `model.joblib` (first Pipeline step), so there is
no separate scaler file to keep in sync. `load_bundle` verifies SHA-256
checksums and refuses bundles built for a different feature list.

## Predict

```bash
PYTHONPATH=ml python -m sentinel_ml predict \
  --bundle models/sentinel-flow/<version> \
  --csv data/raw/cic-ids2017/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
  --limit 5
# {"summary": "ddos detected — confidence 100.0%", "label": "ddos", "confidence": 1.0,
#  "class_probs": {...}, "explanation": [{"feature": "bwd_bytes", "weight": 31.8, ...}]}
```

From Python (what the Phase 5 ML engine will do):

```python
from sentinel_ml import features
from sentinel_ml.inference import Predictor

predictor = Predictor.from_bundle("models/sentinel-flow/<version>")
for p in predictor.predict(features.from_records(flow_dicts)):
    print(p.summary(), p.explanation[:3])
```

## Test

```bash
cd ml && pip install -r requirements-dev.txt
pytest                       # trains on synthetic CIC-format data; no dataset needed
ruff check . && ruff format --check .
```
