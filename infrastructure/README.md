# Infrastructure

Shared infrastructure configuration. Each service's Dockerfile lives next to
its code (`backend/Dockerfile`, `frontend/Dockerfile`); the stack itself is
defined in the root `docker-compose.yml`.

| Path | Purpose |
|---|---|
| `db/init/01-app-role.sh` | Runs once when the PostgreSQL volume is created. Creates `sentinel_app`, the least-privilege role the API and alert engine use: data access on tables created by the schema owner, but no ownership, so it cannot alter the schema or disable the audit-log trigger. |

Planned: `prometheus/`, `grafana/` (optional monitoring profile, Phase 8).
