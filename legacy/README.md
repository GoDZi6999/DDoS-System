# Legacy prototype (NSL-KDD + Flask)

This folder holds the project's first prototype, kept unchanged for reference.
**ArgusAI replaces it** and the folder will be deleted once the new ML
pipeline (Phase 4) matches its functionality.

Why it is being replaced (details in [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §0):

- It trains on NSL-KDD. Several of its features (`hot`, `logged_in`,
  `num_compromised`, `service`) cannot be computed from live packets, so
  `real_time_detection.py` approximates them. Live input therefore does not
  match the data the model was trained on (train/serve skew).
- Preprocessing maps are duplicated between training and live code.
- No authentication, persistence or audit trail.

## Running it (optional)

Run all commands from inside this folder: the scripts use relative `data/`,
`models/` and `logs/` paths.

```bash
cd legacy
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
mkdir -p data logs models            # logging needs logs/ before startup
# put KDDTrain+.txt into data/
python main.py --mode train
python main.py --mode evaluate
python main.py --mode dashboard      # http://localhost:5000
sudo python main.py --mode detect --interface eth0   # live capture needs root
```
