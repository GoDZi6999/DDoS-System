# Infrastructure

Shared infrastructure configuration. Each service's Dockerfile lives next to
its code (`backend/Dockerfile`, `frontend/Dockerfile`); the stack itself is
defined in the root `docker-compose.yml`.

Planned contents:

- `db/init/`: PostgreSQL init scripts, e.g. a least-privilege application role
  that cannot UPDATE/DELETE the append-only audit log (Phase 3)
- `prometheus/`, `grafana/`: optional monitoring profile (Phase 8)
