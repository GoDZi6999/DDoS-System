# Real-time engine (`sentinel_engine`)

Turns traffic into risk-scored detections for the alert engine:

```
live capture / PCAP replay / simulator / capture sensors (flow records via Redis)
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
| Capture sensors | `python -m sentinel_engine run --source sensor` | Classifies flows shipped by sensors on other hosts (below). Used by `docker-compose.sensor.yml`. |

Environment: `REDIS_URL`, `MODEL_BUNDLE` (default `models/sentinel-flow/2026.10.03`),
`FLOW_PROFILES` (default `data/samples/flow_profiles.csv`).

With Docker Compose the engine runs in the `engine` service:

```bash
docker compose exec engine python -m sentinel_engine inject --scenario portscan --duration 20
```

## Capture sensors (real traffic)

Containers under Docker Desktop (Windows, macOS) run in a VM and cannot see the
host's network adapters, and a SOC usually wants to watch several machines or a
switch mirror port anyway. So capture is split from analysis:

```
host A: sensor ─┐  packets -> flows (flows.py), flow statistics only, never payloads
host B: sensor ─┼─> Redis stream sentinel:flows ─> engine --source sensor -> ML, rules, risk
host C: sensor ─┘   status: sentinel:sensors:<name> ─> API GET /api/v1/sensors ─> Sensors page
```

The sensor (`python -m sentinel_engine.sensor`) needs only Scapy and redis-py
(`requirements-sensor.txt`), not the ML stack. It buffers up to 50,000 flows while
the stack is unreachable and catches up when it returns, and reports its health
(packet rate, flows sent, buffered and dropped flows, capture drops) every 5 s.
The engine reads through a consumer group, so a restarted engine resumes where it
stopped, and it validates every entry before classification: sensors are only
trusted as far as their credentials go. The wire contract is in
[`flowstream.py`](sentinel_engine/flowstream.py).

### 1. Start the stack in sensor mode

Set the two Redis passwords in `.env` (`cp .env.example .env`), e.g. with
`openssl rand -hex 24`, then:

```bash
docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d --build --wait
```

Redis is published on `127.0.0.1:6379` for a sensor on the same machine. For
sensors on other hosts, set `SENSOR_BIND=0.0.0.0` (and `SENSOR_PORT`) and keep the
port behind a firewall, VPN or TLS tunnel; sensors log in as the restricted
`sensor` account, which can only append flows and update sensor status.

### 2. Run a sensor

Capture needs administrator/root rights (or `CAP_NET_RAW` on Linux).

**Windows** (install [Npcap](https://npcap.com) first, as Wireshark does), in an
administrator PowerShell from the repository root:

```powershell
python -m venv .sensor-venv
.sensor-venv\Scripts\pip install -r engine\requirements-sensor.txt
$env:PYTHONPATH = "engine"
$env:SENSOR_REDIS_URL = "redis://sensor:<SENSOR_REDIS_PASSWORD>@localhost:6379/0"
.sensor-venv\Scripts\python -m sentinel_engine.sensor --list-interfaces
.sensor-venv\Scripts\python -m sentinel_engine.sensor --interface "Wi-Fi" --name my-laptop
```

`scripts/run_sensor.ps1` does the same in one step.

**Linux / macOS:**

```bash
python3 -m venv .sensor-venv && .sensor-venv/bin/pip install -r engine/requirements-sensor.txt
sudo PYTHONPATH=engine SENSOR_REDIS_URL='redis://sensor:<password>@stack-host:6379/0' \
  .sensor-venv/bin/python -m sentinel_engine.sensor --interface eth0 --name edge-1
```

Within seconds the sensor shows as **Online** on the dashboard's Sensors page, and
detections from real traffic appear on the Overview and Alerts pages with source
`live`. `--filter` takes a BPF expression (e.g. `"not port 6379"`) to leave
traffic out.

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
  ~900 flows/s on 4 cores), not line rate. Several sensors spread capture load; the
  engine side scales by adding replicas to the `engine` consumer group.
- The model was trained on CIC-IDS2017 lab traffic. On a home or office network,
  expect benign traffic the model has never seen (streaming, cloud sync, games) and
  therefore more false positives than on the test set; analysts close them as
  FALSE_POSITIVE, which is the feedback a future retraining needs.
- Sensor clocks should be synchronised (NTP): flows carry the sensor's timestamps.

## Test

```bash
cd engine && pip install -r requirements-dev.txt
pytest          # flow features, window/rule, risk, PCAP replay, sensors, end-to-end, contract
ruff check . && ruff format --check .
```
