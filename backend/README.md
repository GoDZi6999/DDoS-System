# Backend (FastAPI)

REST + WebSocket API and the alert-engine worker for SentinelAI. API
reference: [`docs/API.md`](../docs/API.md); security controls:
[`docs/SECURITY.md`](../docs/SECURITY.md).

The same image runs three ways in `docker-compose.yml`:

| Service | Command | Role |
|---|---|---|
| `migrate` | `alembic upgrade head && python -m app.cli bootstrap` | One-shot, as the schema owner: migrations + first admin |
| `backend` | `uvicorn app.main:app` | API, as the least-privilege `sentinel_app` role |
| `alert-engine` | `python -m app.workers.alert_engine` | Consumes `sentinel:detections` from Redis, stores events, raises alerts |

## Run locally (without Docker)

Requires Python 3.11+, PostgreSQL 14+ and Redis 7. Defaults in
`app/core/config.py` point at `localhost`; override with `DATABASE_URL` and
`REDIS_URL`.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head
INITIAL_ADMIN_PASSWORD='choose-a-long-passphrase' python -m app.cli bootstrap
uvicorn app.main:app --reload            # http://localhost:8000/docs
python -m app.workers.alert_engine       # in another terminal
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
  cli.py               bootstrap admin, synthetic detections
  core/                settings, password hashing, JWT
  db/                  declarative base, engine/session factories
  models/              SQLAlchemy models
  schemas/             Pydantic request/response models; detection.py is the stream contract
  services/            business logic: auth, users, alerts (workflow + correlation),
                       events, stats, audit, detection config, notifications
  api/                 health probes, dependencies (auth, roles), /api/v1 routers, WebSocket
  workers/             alert_engine.py (Redis stream consumer)
alembic/               migrations
tests/                 pytest suite (real PostgreSQL + Redis)
```
