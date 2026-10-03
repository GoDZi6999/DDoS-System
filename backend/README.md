# Backend (FastAPI)

REST + WebSocket API for SentinelAI. In Phase 2 it only exposes the
operational probes; authentication, alerts, events and the WebSocket feed
arrive in Phase 3 (see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) §7).

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness: the process is serving requests |
| `GET /health/ready` | Readiness: PostgreSQL and Redis are reachable (`503` otherwise) |
| `GET /docs` | Swagger UI (OpenAPI) |

## Run locally (without Docker)

Requires Python 3.11+ and running PostgreSQL and Redis. The defaults in
`app/core/config.py` point at `localhost`; override them with
`DATABASE_URL` and `REDIS_URL`.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload          # http://localhost:8000/docs
```

## Test and lint

```bash
pytest
ruff check . && ruff format --check .
```

## Layout

```
app/
  main.py          app factory + lifespan (DB engine, Redis client)
  core/config.py   settings from environment variables
  api/health.py    liveness / readiness probes
tests/             pytest suite
```

Planned for Phase 3: `api/v1/` (versioned routers), `models/` (SQLAlchemy),
`schemas/` (Pydantic), `services/` (alert engine, audit), `ws/`, `alembic/`.
