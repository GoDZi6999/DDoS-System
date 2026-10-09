# Backend (FastAPI)

REST + WebSocket API and the background workers (alert engine, notifier) for ArgusAI. API
reference: [`docs/API.md`](../docs/API.md); security controls:
[`docs/SECURITY.md`](../docs/SECURITY.md).

The same image runs five ways in `docker-compose.yml`:

| Service | Command | Role |
|---|---|---|
| `migrate` | `alembic upgrade head && python -m app.cli bootstrap` | One-shot, as the schema owner: migrations + first admin |
| `backend` | `uvicorn app.main:app` | API (`/api/v1` for the dashboard, `/v2` for customer applications), as the least-privilege `sentinel_app` role |
| `alert-engine` | `python -m app.workers.alert_engine` | Consumes `sentinel:detections` from Redis, stores events, raises alerts, queues notifications |
| `capture-worker` | `python -m app.workers.capture_analyzer` | Analyses uploaded packet captures through the engine (`sentinel_engine`); detections go to the alert engine |
| `notifier` | `python -m app.workers.notifier` | Sends queued notifications (email, Slack, webhook) with retries; applies data retention every 6 h |

The image builds from the repository root (`docker build -f backend/Dockerfile .`)
because `/v2/detect` and capture analysis need the shared ML package
(`ml/sentinel_ml`), the engine (`engine/sentinel_engine`) and the model bundles.

## Run locally (without Docker)

Requires Python 3.11+, PostgreSQL 14+ and Redis 7. Defaults in
`app/core/config.py` point at `localhost`; override with `DATABASE_URL` and
`REDIS_URL`.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt     # includes ../ml/requirements.txt
export PYTHONPATH=../ml:../engine       # sentinel_ml and sentinel_engine
alembic upgrade head
INITIAL_ADMIN_PASSWORD='choose-a-long-passphrase' python -m app.cli bootstrap
uvicorn app.main:app --reload            # http://localhost:8000/docs
python -m app.workers.alert_engine       # in another terminal
python -m app.workers.notifier           # optional: notifications + retention
python -m app.workers.capture_analyzer   # optional: packet capture analysis
```

## Tests and lint

The suite runs against real PostgreSQL and Redis (the schema uses INET,
JSONB, triggers and advisory locks). It creates and migrates its own database,
`sentinel_test`, and uses Redis database 15.

```bash
docker run -d --name sentinel-test-pg -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=sentinel -e POSTGRES_DB=sentinel postgres:16-alpine
docker run -d --name sentinel-test-redis -p 127.0.0.1:6379:6379 redis:7-alpine

pytest                                   # TEST_DATABASE_URL / TEST_REDIS_URL to override
ruff check . && ruff format --check .
```

## Migrations

```bash
alembic revision --autogenerate -m "describe the change"   # then review the file
alembic upgrade head
```

`tests/test_migrations.py` fails if the models and migrations drift apart and
checks that every migration downgrades and upgrades cleanly.

## Layout

```
app/
  main.py              app factory, lifespan, security headers, error mapping
  cli.py               bootstrap admin, password reset, synthetic detections, purge
  core/                settings, password hashing, JWT
  db/                  declarative base, engine/session factories
  models/              SQLAlchemy models
  schemas/             Pydantic request/response models; detection.py is the stream contract
  services/            business logic: auth, users, alerts (workflow + correlation),
                       events, stats, audit, detection config, notifications
                       (outbox), senders (SMTP/Slack/webhook), retention,
                       API keys, detector (model for /v2/detect), flow ingest,
                       captures + capture_analysis (uploads, replay, evidence)
  api/                 health probes, dependencies (auth, roles), /api/v1 routers, WebSocket,
                       /v2 customer API (API-key auth: detect, flow ingest)
  workers/             alert_engine.py (Redis stream consumer), notifier.py (outbox sender),
                       capture_analyzer.py (uploaded packet captures)
alembic/               migrations
tests/                 pytest suite (real PostgreSQL + Redis)
```
