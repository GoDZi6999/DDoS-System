# Tests

Tests live next to the code they cover; this folder only maps them. The full
guide, with what each layer proves and how to run it, is
[`docs/TESTING.md`](../docs/TESTING.md).

| Layer | Location | Runs against |
|---|---|---|
| Backend (API, workers, migrations, RBAC matrix) | `backend/tests/` | real PostgreSQL + Redis |
| ML pipeline (features, training, explanations, bundles) | `ml/tests/` | synthetic CIC-format data |
| Real-time engine (flows, rules, risk, contract) | `engine/tests/` | the committed model bundle |
| Stack smoke test | `scripts/smoke_test.sh` | `docker compose up` |
| Dashboard end to end (Playwright) | `frontend/e2e/` | `docker compose up` |
| Benchmarks | `python -m argus_engine bench`, `scripts/benchmark_stack.py` | in process / running stack |
