# Cross-service tests

Unit tests live with their component (`backend/tests/`, later `ml/` and
`collector/`). This folder is for tests that span several services:

- `integration/`: API + PostgreSQL + Redis against the Compose stack (Phase 3)
- `ml-regression/`: metric floors and the offline/online feature-parity check (Phase 4)
- `e2e/`: Playwright, from login -> live alert -> acknowledge -> resolve (Phase 6)

The current end-to-end check is `scripts/smoke_test.sh`, run by CI against
`docker compose up`.
