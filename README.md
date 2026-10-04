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
[security controls](docs/SECURITY.md) · [ML methodology](docs/ML_METHODOLOGY.md) ·
[datasets](data/README.md).

**Current model** (XGBoost on CIC-IDS2017, held-out test set of 652,904 flows):
99.48% accuracy, 99.27% of attack flows detected, 0.20% of benign flows
flagged, ~1 ms per flow, with a SHAP explanation for every attack. Port scans
and botnet traffic are the weak spot per flow; see the
[report](ml/reports/2026.10.03/report.md) for per-class results and caveats.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Architecture | ✅ Done |
| 2 | Repository skeleton, Docker Compose, CI | ✅ Done |
| 3 | Backend: auth/RBAC, database, alert engine + workflow, audit log, WebSocket | ✅ Done |
| 4 | ML pipeline: CIC-IDS2017, LR / RF / XGBoost, evaluation, SHAP, model bundles | ✅ Done |
| 5 | Real-time engine: flow builder, PCAP replay, live capture, simulator, port-scan rule, risk engine | ✅ Done |
| 6 | SOC dashboard on the live API: overview, live traffic, alerts workflow, audit, settings, users | ✅ Done |
| 7 | Notifications (email, Slack, signed webhooks) with retries and per-alert de-duplication; data retention | ✅ Done |
| 8 | Documentation, performance, optional monitoring | ⏳ Next |

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
| <http://localhost:3000> | SOC dashboard; sign in as `admin` with the password above |
| <http://localhost:3000/status> | Public stack status page (no login) |
| <http://localhost:8000/docs> | API documentation; **Authorize** with `admin` and the password above |
| <http://localhost:8000/health/ready> | Readiness of PostgreSQL and Redis |

The real-time engine starts with simulated lab traffic (nothing is sent on
any network). Trigger an attack and watch the alert appear on the dashboard
within seconds, without reloading, or run the whole demo story on a loop:

```bash
docker compose exec engine python -m sentinel_engine inject --scenario ddos --duration 20
ENGINE_SCENARIO=demo docker compose up -d engine     # normal -> DDoS -> port scan -> ...
```

PCAP replay and live capture are described in [`engine/README.md`](engine/README.md).

**Notifications.** Admins add email, Slack or webhook channels under
*Notifications* in the dashboard; each channel hears about an alert once per
severity band, with retries and a delivery log. To try email without a real
mail server, start the bundled mail catcher and open <http://localhost:8025>:

```bash
COMPOSE_PROFILES=mail SMTP_HOST=mailpit SMTP_PORT=1025 SMTP_SECURITY=none \
  docker compose up -d --wait
```

For a real relay set the `SMTP_*` variables in `.env` (see `.env.example`).
The notifier also enforces data retention (flows kept 14 days unless they are
evidence for an alert; the audit log is never purged).

Check the whole stack with `ADMIN_PASSWORD=… ./scripts/smoke_test.sh` (add
`MAILPIT_URL=http://localhost:8025` with the mail profile to verify alert emails), and the
dashboard end to end with `cd frontend && ADMIN_PASSWORD=… npm run test:e2e`
(Playwright: sign in, live DDoS alert, acknowledge → contain → resolve). Stop it
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
  the Compose stack and runs the authenticated smoke test and the Playwright
  end-to-end tests against it.

## Repository layout

```
backend/          FastAPI service (REST, WebSocket, auth, alerts) + alert-engine worker
frontend/         Next.js SOC dashboard
ml/               sentinel_ml: shared features, training, evaluation, SHAP, inference
engine/           real-time engine: capture/replay/simulator, flow builder, rules, risk
data/             dataset instructions; raw data is never committed
models/           versioned model bundles (current one committed, ~2 MB)
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
- The dashboard keeps API tokens server-side in httpOnly cookies
  (backend-for-frontend); browser JavaScript never sees them.
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
