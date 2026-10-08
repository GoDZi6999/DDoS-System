# SentinelAI

**Real-time AI-powered network threat detection and SOC platform.**

SentinelAI classifies network flows in real time with an explainable model,
scores their risk and raises alerts that analysts work through a SOC-style
workflow, with notifications and a tamper-resistant audit trail. It
**detects and alerts; it does not block traffic**. Its recommended actions are
advisory.

![SOC overview during a simulated DDoS](docs/images/overview.png)

```
traffic: simulator | PCAP replay | live capture | capture sensors
   -> flow builder (CICFlowMeter-style, 37 features) -> XGBoost + SHAP + port-scan rule -> risk score
   -> Redis stream -> alert engine -> PostgreSQL (events, alerts, audit, notification outbox)
   -> FastAPI (REST + WebSocket) -> Next.js SOC dashboard (backend-for-frontend)
   -> notifier -> email / Slack / signed webhooks
```

## Highlights

- **Model you can check.** XGBoost on CIC-IDS2017, evaluated on a held-out
  set of 652,904 flows after deduplication and a temporal split: 99.48%
  accuracy, 99.27% of attack flows detected, 0.20% of benign flows flagged.
  Every alert carries the SHAP factors behind it. An opt-in candidate model
  (2026.10.04) halves false positives (0.11%) at some cost in botnet recall.
  Per-class results, the weak spots and the release gate are in the
  [ML methodology](docs/ML_METHODOLOGY.md).
- **Real time.** A flow becomes a committed alert in ~1.7 s. The engine
  classifies ~10,000 flows/s during a flood; one alert absorbs the flood and
  escalates with its risk. See [performance](docs/PERFORMANCE.md).
- **SOC console.** A dark analyst console with a live threat level, event feed
  and traffic chart; the workflow runs NEW → INVESTIGATING → CONTAINED →
  RESOLVED (or false positive) with assignment, notes, history, a risk
  breakdown and a recommended action. Three roles: admin, analyst, viewer.
- **Notifications that don't flood.** Email, Slack and HMAC-signed webhooks,
  queued in the same transaction as the alert change, retried with backoff,
  sent once per alert severity band.
- **Security built in.** argon2id, short-lived tokens with refresh-token theft
  detection, a role matrix tested for every endpoint, an audit log PostgreSQL
  itself keeps append-only, tokens kept out of the browser, SSRF-guarded
  webhooks. See [security controls](docs/SECURITY.md).
- **Runs anywhere Docker does.** `docker compose up` gives the whole stack with
  a safe simulator; an optional profile adds Prometheus and Grafana.

| | |
|---|---|
| ![Alert detail with SHAP explanation](docs/images/alert-detail.png) | ![Sign-in screen](docs/images/login.png) |

## Quick start

Requires Docker with Compose v2.

```bash
git clone https://github.com/GoDZi6999/DDoS-System.git && cd DDoS-System
docker compose up --build -d --wait
docker compose logs migrate      # first start: the generated admin password, shown once
```

| URL | What |
|---|---|
| <http://localhost:3000> | SOC dashboard; sign in as `admin` |
| <http://localhost:3000/status> | Public status page (no login) |
| <http://localhost:8000/docs> | API documentation (**Authorize** with the same account) |

Then simulate an attack and watch it arrive on the dashboard:

```bash
docker compose exec engine python -m sentinel_engine inject --scenario ddos --duration 30
```

The [demo walkthrough](docs/DEMO.md) covers the rest: investigating an
alert, notifications, roles, monitoring and replaying your own PCAP. Lost the
password? Run `docker compose exec backend python -m app.cli reset-password admin`.

### Monitor real traffic

To classify your own network's traffic instead of the simulator's, run the stack
with the sensor overlay and start a capture sensor on each machine to watch
(Windows, Linux or macOS; containers under Docker Desktop cannot see the host's
adapters, so capture runs natively and ships flow statistics to the stack):

```bash
# .env: set REDIS_PASSWORD and SENSOR_REDIS_PASSWORD first (see .env.example)
docker compose -f docker-compose.yml -f docker-compose.sensor.yml up -d --build --wait
```

```powershell
.\scripts\run_sensor.ps1 -Interface "Wi-Fi" -Name my-laptop   # Windows, admin PowerShell
```

The sensor appears on the dashboard's **Sensors** page and its traffic flows into
the Overview and Alerts pages. Linux/macOS and multi-host setup:
[`engine/README.md`](engine/README.md#capture-sensors-real-traffic).

**Optional profiles**

```bash
COMPOSE_PROFILES=mail SMTP_HOST=mailpit SMTP_PORT=1025 SMTP_SECURITY=none docker compose up -d --wait
#   catches alert emails locally: http://localhost:8025
COMPOSE_PROFILES=monitoring docker compose up -d --wait
#   Prometheus http://localhost:9090, Grafana http://localhost:3001
```

**Configuration.** Every setting has a development default, so no `.env` is
needed to start. For anything shared, `cp .env.example .env`, then set an
admin password, `JWT_SECRET`, database passwords, SMTP settings and
`COOKIE_SECURE=true`. Put a TLS reverse proxy in front (see
[security](docs/SECURITY.md)).

## Documentation

| Document | Contents |
|---|---|
| [Demo walkthrough](docs/DEMO.md) | Ten-minute tour from a fresh clone |
| [Architecture](docs/ARCHITECTURE.md) | Components, data flow, schema, decisions, threat model |
| [API](docs/API.md) | REST and WebSocket reference, roles, workflow, notifications, detection contract |
| [ML methodology](docs/ML_METHODOLOGY.md) | Data, features, split, models, results, explainability, threats to validity |
| [Security](docs/SECURITY.md) | Implemented controls with their tests, known gaps |
| [Performance](docs/PERFORMANCE.md) | Measured throughput and latency, how to reproduce |
| [Testing](docs/TESTING.md) | Test layers, what each proves, how to run them |
| Component READMEs | [backend](backend/README.md) · [frontend](frontend/README.md) · [ml](ml/README.md) · [engine](engine/README.md) · [data](data/README.md) · [models](models/README.md) · [infrastructure](infrastructure/README.md) · [scripts](scripts/README.md) |

## Status

All eight planned phases are complete:

| Phase | Scope |
|---|---|
| 1 | Architecture |
| 2 | Repository skeleton, Docker Compose, CI |
| 3 | Backend: auth/RBAC, database, alert engine and workflow, audit log, WebSocket |
| 4 | ML pipeline: CIC-IDS2017, LR / RF / XGBoost, evaluation, SHAP, model bundles |
| 5 | Real-time engine: flow builder, PCAP replay, live capture, simulator, port-scan rule, risk engine |
| 6 | SOC dashboard on the live API |
| 7 | Notifications (email, Slack, signed webhooks) and data retention |
| 8 | Performance work and benchmarks, optional monitoring, documentation |

A mitigation phase (dry-run policies with allow-lists, rate caps and human
approval) is deliberately not built: it should only follow a false-positive
rate validated on the target network.

## Repository layout

```
backend/          FastAPI API, alert engine and notifier workers, migrations, tests
frontend/         Next.js SOC dashboard (backend-for-frontend), Playwright E2E
ml/               sentinel_ml: shared features, training, evaluation, SHAP, inference
engine/           real-time engine: simulator / PCAP / live capture, flows, rules, risk
models/           versioned model bundle (committed, ~2 MB, checksum-verified)
data/             dataset instructions and the simulator's flow profiles (no raw data)
infrastructure/   DB init (least-privilege role), Prometheus and Grafana config
scripts/          smoke test and stack benchmark
docs/             documentation and screenshots
legacy/           original NSL-KDD + Flask prototype, superseded, kept for reference
```

## Limitations

Read these before relying on SentinelAI:

- **One training dataset.** All model numbers come from CIC-IDS2017, a lab
  capture. Expect lower accuracy on other networks until the model is
  validated (or retrained) on representative traffic. The simulator replays
  held-out CIC-IDS2017 statistics, so the demo shows the model on traffic like
  its test set, not generalisation.
- **Weak classes.** Port scans and botnet traffic are hard to recognise per
  flow (low precision). A window rule catches scans by port count.
- **False positives.** About 0.2% of benign flows are flagged, so a busy
  network sees regular low-confidence alerts for analysts to dismiss.
- **Flow statistics only.** Encrypted or application-layer attacks are visible
  only through their traffic shape; there is no payload inspection.
- **Capture scale.** Live capture uses Scapy: fine for labs and small
  networks, not line rate. Classification and alerting are faster (see
  [performance](docs/PERFORMANCE.md)) and are not the bottleneck.
- **Explanations.** SHAP explains the model's reasoning, not ground-truth
  causality, and floods are explained on a sample of their flows.
- **Adversarial traffic** crafted to look benign is not defended against.
- **Deployment.** The defaults are for local use; TLS, real secrets and a
  reverse proxy are required for anything shared. Remaining security gaps are
  listed in [SECURITY.md](docs/SECURITY.md#known-gaps-and-residual-risks).

## Datasets and licence notes

Training uses CIC-IDS2017 (Canadian Institute for Cybersecurity), which you
download yourself; see [`data/README.md`](data/README.md) for the layout and
citation. The repository ships only the trained model bundle and a small file
of derived flow profiles for the simulator.

## Legacy prototype

The original NSL-KDD + Flask prototype in [`legacy/`](legacy/README.md) is
superseded by SentinelAI and kept only for reference; nothing in the stack
uses it.
