# Real-time engine (`sentinel_engine`)

Turns traffic into risk-scored detections for the alert engine:

```
live capture / PCAP replay / simulator
   -> flow builder (flows.py)              packets -> bidirectional flows -> 37 features
   -> window stats (window.py)             cross-flow behaviour over 10 s
   -> classifier (sentinel_ml Predictor)   label, confidence, SHAP explanation
   -> port-scan rule (pipeline.py)         >= 20 distinct ports from one source in 10 s
   -> risk engine (risk.py)                0-100 score with its four components
   -> Redis: sentinel:detections stream (alert engine), traffic.tick events (dashboards)
```

Detections follow the contract in [`docs/schemas/detection.schema.json`](../docs/schemas/detection.schema.json);
the tests validate the engine's output against it.

## Sources

| Source | Command | Notes |
|---|---|---|
| Simulator (default) | `python -m sentinel_engine run --source simulate --scenario normal --loop` | Sends nothing on any network. Benign and attack flows replay **real held-out CIC-IDS2017 flow statistics** (`data/samples/flow_profiles.csv`) with lab addresses; port scans are generated as packets and go through the flow builder. |
| Demo story | `--scenario demo --loop` (or `ENGINE_SCENARIO=demo docker compose up`) | normal → DDoS ramp → normal → port scan → DoS → brute force → web attack → botnet, ~6.5 min per cycle. |
| One attack burst | `python -m sentinel_engine inject --scenario ddos --duration 20` | Also `dos`, `portscan`, `bruteforce`, `webattack`, `botnet`. |
| PCAP replay | `python -m sentinel_engine run --source pcap --pcap capture.pcap --speed 2` | Timestamps are shifted to "now" unless `--no-retime`. |
| Live capture | `sudo python -m sentinel_engine run --source live --interface eth0 [--filter "tcp or udp"]` | Read-only sniffing; needs `CAP_NET_RAW`. Run it on the host whose traffic you want to see, with `REDIS_URL` pointing at the stack's Redis. |

Environment: `REDIS_URL`, `MODEL_BUNDLE` (default `models/sentinel-flow/2026.10.03`),
`FLOW_PROFILES` (default `data/samples/flow_profiles.csv`).

With Docker Compose the engine runs in the `engine` service:

```bash
docker compose exec engine python -m sentinel_engine inject --scenario portscan --duration 20
```

## Risk score

`risk = 0.40·ml_confidence + 0.25·traffic_anomaly + 0.25·attack_severity + 0.10·source_reputation`

- **ml_confidence**: probability of the predicted attack class × 100 (0.9 for the rule).
- **traffic_anomaly**: packet rate towards the destination (10 s window) against its
  benign baseline (EWMA of log rate, robust z-score). The baseline is frozen while the
  destination is under attack, and for 60 s after, so a flood cannot become "normal".
- **attack_severity**: ddos 90, dos 80, botnet 80, webattack 70, bruteforce 65, portscan 50.
- **source_reputation**: 20 points per attack detection from the same source in the last hour.

Weights follow the admin-editable detection settings (`PUT /api/v1/config/detection`),
which the API mirrors to Redis; the engine re-reads them every 10 s. Benign flows score 0.

## Honest limits

- The simulator's attack statistics come from CIC-IDS2017, so a demo shows the model on
  traffic like its test set; it does not show generalisation to other networks.
- With the default `normal` scenario, occasional false-positive alerts appear (benign flows
  the model misclassifies, ~0.2% on the test set). That is expected; analysts close them
  as FALSE_POSITIVE.
- The flow builder follows CICFlowMeter's definitions but has not yet been checked
  feature-by-feature against CICFlowMeter on the same capture.
- Pure-Python capture suits lab and small networks (the simulated pipeline processes
  ~900 flows/s on 4 cores), not line rate.

## Test

```bash
cd engine && pip install -r requirements-dev.txt
pytest          # flow features, window/rule, risk, PCAP replay, end-to-end scenarios, contract
ruff check . && ruff format --check .
```
