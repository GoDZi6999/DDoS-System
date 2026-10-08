# Infrastructure

Shared infrastructure configuration. Each service's Dockerfile lives next to
its code; the stack is defined in the root `docker-compose.yml`.

| Path | Purpose |
|---|---|
| `db/init/01-app-role.sh` | Runs once when the PostgreSQL volume is created. Creates `sentinel_app`, the least-privilege role the API and workers use: data access on tables created by the schema owner, but no ownership, so it cannot alter the schema or disable the audit-log trigger. |
| `prometheus/prometheus.yml` | Scrape configuration for the optional `monitoring` profile: the API's `/metrics` every 15 s. |
| `grafana/provisioning/` | Grafana data source (Prometheus) and dashboard provider, loaded read-only. |
| `grafana/dashboards/sentinelai.json` | The provisioned ArgusAI operations dashboard: open alerts by severity, flows per second (benign/attack), detection-stream backlog, notification outcomes, API request rate and p95 latency. |

Start monitoring with `COMPOSE_PROFILES=monitoring docker compose up -d`, then
open Grafana at <http://localhost:3001> (user `admin`, password
`GRAFANA_ADMIN_PASSWORD`) or Prometheus at <http://localhost:9090>.
