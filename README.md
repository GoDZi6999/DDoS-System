# SentinelAI

**Real-time AI-powered network threat detection and SOC platform.**

SentinelAI detects and classifies suspicious network traffic in real time and
raises risk-scored, explainable security alerts that analysts work through a
SOC-style workflow. It does **not** claim to prevent attacks: mitigation is a
future, opt-in phase with safeguards.

```
Live traffic / PCAP replay -> Flow builder -> Feature extraction -> ML engine (RF / XGBoost)
  -> SHAP explanation + risk score -> Redis -> FastAPI (REST + WebSocket) -> Next.js SOC dashboard
                                                     |-> PostgreSQL       |-> Email / Slack / webhook
```

Full design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Architecture | ✅ Done |
| 2 | Repository skeleton, Docker Compose, CI | ✅ Done |
| 3 | Backend: auth/RBAC, database, alerts API, audit log, WebSocket | ⏳ Next |
| 4 | ML pipeline: CIC datasets, LR / RF / XGBoost, evaluation, SHAP, model bundles | ⏳ |
| 5 | Real-time engine: Scapy collector, PCAP replay, lab simulator, risk engine | ⏳ |
| 6 | SOC dashboard on the live API | ⏳ |
| 7 | Notifications and background workers | ⏳ |
| 8 | Documentation, performance, optional monitoring | ⏳ |

## Quick start

Requires Docker with Compose v2.

```bash
git clone https://github.com/GoDZi6999/DDoS-System.git
cd DDoS-System
docker compose up --build        # add -d --wait to run in the background
```

| URL | What |
|---|---|
| <http://localhost:3000> | Dashboard (Phase 2: stack status page) |
| <http://localhost:8000/docs> | API documentation (Swagger / OpenAPI) |
| <http://localhost:8000/health/ready> | Readiness of PostgreSQL and Redis |

Check the whole stack with `./scripts/smoke_test.sh`. Stop it with
`docker compose down` (add `-v` to delete the database volume as well).

### Configuration

Every setting has a development default, so no `.env` file is needed to start.
To change passwords or ports: `cp .env.example .env` and edit it.

## Development

- Backend (FastAPI, Python 3.11+): see [`backend/README.md`](backend/README.md)
- Frontend (Next.js 16, Tailwind 4): see [`frontend/README.md`](frontend/README.md)
- CI (GitHub Actions) runs backend lint + tests, frontend lint + build + a
  production dependency audit, then builds the Compose stack and runs the smoke test.

## Repository layout

```
backend/          FastAPI service (REST, WebSocket, auth, alerts)
frontend/         Next.js SOC dashboard
ml/               training, evaluation, shared feature code, inference   (Phase 4)
collector/        Scapy capture, PCAP replay, flow builder               (Phase 5)
simulator/        safe lab traffic generator                             (Phase 5)
data/             dataset instructions; raw data is never committed
models/           versioned model bundles (not committed)
infrastructure/   shared infra config (DB init, monitoring)
tests/            cross-service integration / E2E / ML-regression tests
scripts/          smoke test and helper scripts
docs/             architecture and project documentation
legacy/           original NSL-KDD + Flask prototype, kept for reference
```

## Datasets

Training uses public datasets (CIC-IDS2017, CIC-DDoS2019, UNSW-NB15). See
[`data/README.md`](data/README.md) for downloads, layout and citations.

## Security notes

- Published ports bind to `127.0.0.1` only; PostgreSQL and Redis are not
  published at all and sit on an internal network with no internet route.
- Application containers run as non-root users.
- The defaults are for local development. Change the passwords in `.env`
  before running the stack anywhere shared.

## Limitations

Detection quality is bounded by the training data; encrypted or
application-layer attacks are only visible through flow statistics; Scapy
capture suits lab and small networks, not line-rate backbones; SHAP explains
the model's reasoning, not ground-truth causality.

## Legacy prototype

The original NSL-KDD + Flask implementation lives in [`legacy/`](legacy/README.md)
and will be removed once the new ML pipeline replaces it.
