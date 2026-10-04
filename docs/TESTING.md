# Testing

Every layer is tested against real dependencies, and CI runs all of it on each
push (`.github/workflows/ci.yml`).

| Layer | Where | What it proves | Run |
|---|---|---|---|
| Backend | `backend/tests/` (143 tests) | API behaviour, the full role matrix (fails if a new endpoint is not listed), auth and token theft detection, alert correlation and workflow, the audit log's tamper resistance, the alert engine's at-least-once delivery and batching, notifications (outbox, de-duplication, retries, signing, SSRF guard), retention, metrics, migration drift | `cd backend && pytest` (needs PostgreSQL and Redis, see `backend/README.md`) |
| ML | `ml/tests/` (18) | Feature parity between CSV and live records, cleaning and labels, temporal split, every candidate model trains and explains, bundle checksums | `cd ml && pytest` |
| Engine | `engine/tests/` (19) | Flow features from hand-made packets, port-scan rule, risk scoring (a flood cannot poison the baseline), PCAP replay, end-to-end scenarios, explanation budget, detections match the JSON Schema contract | `cd engine && pytest` |
| Frontend | `frontend/` | Lint, type check, production build, audit of production dependencies | `npm run lint && npm run build` |
| Stack smoke test | `scripts/smoke_test.sh` | `docker compose up` works end to end: health, metrics, dashboard session guard and CSRF check, login, engine traffic stored, simulated DDoS raises an alert from the trained model, alert email delivered (with the mail profile), audit log append-only for the app's database role | `ADMIN_PASSWORD=… ./scripts/smoke_test.sh` |
| Dashboard E2E | `frontend/e2e/` (Playwright, 4 tests) | Sign-in and refusal of bad credentials; live feed; injected DDoS appears without reload and is worked through acknowledge → assign → note → contain → resolve, visible in the audit log; settings; adding an email channel and delivering its test message | `cd frontend && ADMIN_PASSWORD=… npm run test:e2e` |
| Benchmarks | `python -m sentinel_engine bench`, `scripts/benchmark_stack.py` | Throughput and latency (not pass/fail) | see [`PERFORMANCE.md`](PERFORMANCE.md) |

## Principles

- **No mocks for the database or Redis.** The schema relies on PostgreSQL
  features (INET, JSONB, triggers, advisory locks) and the pipeline on Redis
  streams; the tests use real services (CI service containers).
- **Contracts are tested from both sides.** The detection JSON Schema is
  checked against the backend's Pydantic model and against the engine's output.
- **Security properties have tests.** Each control in
  [`SECURITY.md`](SECURITY.md) names the test that verifies it.
- **The browser tests drive the real stack.** They inject traffic through the
  engine and check outcomes in the UI, the API and the mail catcher.

## In CI

1. `backend`, `ml`, `engine`, `frontend` jobs in parallel (lint, format, tests, build, audit).
2. `stack` (needs all four): builds the Compose stack with the mail profile,
   runs the smoke test and the Playwright suite, uploads the Playwright report
   on failure, prints service logs on failure.
