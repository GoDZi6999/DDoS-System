# Real-time engine (`argus_engine`)

Turns traffic into risk-scored detections for the alert engine:

```
live capture / PCAP replay / simulator
   -> flow builder (flows.py)              packets -> bidirectional flows -> 37 features
   -> window stats (window.py)             cross-flow behaviour over 10 s
   -> classifier (argus_ml Predictor)   label, confidence, SHAP explanation
   -> port-scan rule (pipeline.py)         >= 20 distinct ports from one source in 10 s
   -> risk engine (risk.py)                0-100 score with its four components
   -> Redis: argus:detections stream (alert engine), traffic.tick events (dashboards)
```

Detections follow the contract in [`docs/schemas/detection.schema.json`](../docs/schemas/detection.schema.json);
the tests validate the engine's output against it.

## Sources

| Source | Command | Notes |
|---|---|---|
| Simulator (default) | `python -m argus_engine run --source simulate --scenario normal --loop` | Sends nothing on any network. Benign and attack flows replay **real held-out CIC-IDS2017 flow statistics** (`data/samples/flow_profiles.csv`) with lab addresses; port scans are generated as packets and go through the flow builder. |
| Demo story | `--scenario demo --loop` (or `ENGINE_SCENARIO=demo docker compose up`) | normal → DDoS ramp → normal → port scan → DoS → brute force → web attack → botnet, ~6.5 min per cycle. |
| One attack burst | `python -m argus_engine inject --scenario ddos --duration 20` | Also `dos`, `portscan`, `bruteforce`, `webattack`, `botnet`. |
| PCAP replay | `python -m argus_engine run --source pcap --pcap capture.pcap --speed 2` | Timestamps are shifted to "now" unless `--no-retime`. |
| Live capture | `sudo python -m argus_engine run --source live --interface eth0 [--filter "tcp or udp"]` | Read-only sniffing; needs `CAP_NET_RAW`. Run it on the host whose traffic you want to see, with `REDIS_URL` pointing at the stack's Redis. |

Environment: `REDIS_URL`, `MODEL_BUNDLE` (default `models/argus-flow/2026.10.03`; the
opt-in candidate is `models/argus-flow/2026.10.04`),
`FLOW_PROFILES` (default `data/samples/flow_profiles.csv`).

With Docker Compose the engine runs in the `engine` service:

```bash
docker compose exec engine python -m argus_engine inject --scenario portscan --duration 20
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

## Performance

```bash
python -m argus_engine bench          # needs no Redis; prints a Markdown report
```

On a 4-core VM: ~4.7 ms per benign flow and ~11 ms per attack flow when
classified one at a time; in one-second batches of 100 flows, ~9,500 flows/s
of benign traffic and ~10,000 flows/s during a flood. SHAP explanations cost
about ten times a prediction, so each (attack type, destination) gets at most
5 explained flows per second (`EXPLAIN_PER_TARGET_S`); the other attack flows
carry an empty explanation and the alert keeps the explanation it has. Full
numbers and method: [`docs/PERFORMANCE.md`](../docs/PERFORMANCE.md).

## Honest limits

- The simulator's attack statistics come from CIC-IDS2017, so a demo shows the model on
  traffic like its test set; it does not show generalisation to other networks.
- With the default `normal` scenario, occasional false-positive alerts appear (benign flows
  the model misclassifies, ~0.2% on the test set). That is expected; analysts close them
  as FALSE_POSITIVE.
- The flow builder follows CICFlowMeter's definitions but has not yet been checked
  feature-by-feature against CICFlowMeter on the same capture.
- Classification keeps up with ~10,000 flows/s, but packet capture and flow assembly
  with Scapy are pure Python: they suit lab and small networks, not line rate.

## Test

```bash
cd engine && pip install -r requirements-dev.txt
pytest          # flow features, window/rule, risk, PCAP replay, end-to-end scenarios, contract
ruff check . && ruff format --check .
```
