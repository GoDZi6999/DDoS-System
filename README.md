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

Documentation: [architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) ·
[security controls](docs/SECURITY.md) · [datasets](data/README.md).

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Architecture | ✅ Done |
| 2 | Repository skeleton, Docker Compose, CI | ✅ Done |
| 3 | Backend: auth/RBAC, database, alert engine + workflow, audit log, WebSocket | ✅ Done |
| 4 | ML pipeline: CIC datasets, LR / RF / XGBoost, evaluation, SHAP, model bundles | ⏳ Next |
| 5 | Real-time engine: Scapy collector, PCAP replay, lab simulator, risk engine | ⏳ |
| 6 | SOC dashboard on the live API | ⏳ |
| 7 | Notifications and background workers | ⏳ |
| 8 | Documentation, performance, optional monitoring | ⏳ |

## Quick start

Requires Docker with Compose v2.

```bash
git clone https://github.com/GoDZi6999/DDoS-System.git
cd DDoS-System
docker compose up --build -d --wait
docker compose logs migrate      # first start: shows the generated admin password
```

Lost the password? `docker compose exec backend python -m app.cli reset-password admin`
prints a new one (and records the reset in the audit log).

| URL | What |
|---|---|
| <http://localhost:3000> | Dashboard (until Phase 6: stack status page) |
| <http://localhost:8000/docs> | API documentation; **Authorize** with `admin` and the password above |
| <http://localhost:8000/health/ready> | Readiness of PostgreSQL and Redis |

Until the ML engine (Phase 4/5) exists, you can push clearly labelled
synthetic detections through the real pipeline and watch an alert appear in
`GET /api/v1/alerts`:

```bash
docker compose exec alert-engine python -m app.cli demo-detections --count 20
```

Check the whole stack with `ADMIN_PASSWORD=… ./scripts/smoke_test.sh`. Stop it
with `docker compose down` (add `-v` to delete the database volume as well).

> Upgrading from Phase 2: run `docker compose down -v` once. The database role
> used by the API is created only when the volume is first initialised.

### Configuration

Every setting has a development default, so no `.env` file is needed to start.
To set an admin password, a JWT signing key, database passwords or ports:
`cp .env.example .env` and edit it.

## Development

- Backend (FastAPI, Python 3.11+): see [`backend/README.md`](backend/README.md)
- Frontend (Next.js 16, Tailwind 4): see [`frontend/README.md`](frontend/README.md)
- CI (GitHub Actions) runs backend lint + tests (against real PostgreSQL and
  Redis), frontend lint + build + a production dependency audit, then builds
  the Compose stack and runs the authenticated smoke test.

## Repository layout

```
backend/          FastAPI service (REST, WebSocket, auth, alerts) + alert-engine worker
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

## Security

Highlights (full list, tests and known gaps in [`docs/SECURITY.md`](docs/SECURITY.md)):

- argon2id passwords, 15-minute access tokens, single-use refresh tokens with
  theft detection, login throttling, role checks on every endpoint (tested as
  a full matrix).
- Append-only audit log enforced by PostgreSQL itself; the API's database
  role cannot alter or delete entries.
- Ports bind to `127.0.0.1`; PostgreSQL and Redis sit on an internal network;
  containers run as non-root.
- The defaults are for local development. Set real secrets in `.env` and put
  a TLS reverse proxy in front before running the stack anywhere shared.

## Limitations

Detection quality is bounded by the training data; encrypted or
application-layer attacks are only visible through flow statistics; Scapy
capture suits lab and small networks, not line-rate backbones; SHAP explains
the model's reasoning, not ground-truth causality.

## Legacy prototype

The original NSL-KDD + Flask implementation lives in [`legacy/`](legacy/README.md)
and will be removed once the new ML pipeline replaces it.
