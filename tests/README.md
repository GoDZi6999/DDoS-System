# Cross-service tests

Unit and integration tests live with their component. `backend/tests/` already
runs the API, alert engine and migrations against real PostgreSQL and Redis
(including the role matrix and the WebSocket feed).

This folder is for tests that span several services:

- `ml-regression/`: metric floors and the offline/online feature-parity check (Phase 4)
- `e2e/`: Playwright, from login -> live alert -> acknowledge -> resolve (Phase 6)

The current end-to-end check is `scripts/smoke_test.sh`, which CI runs against
`docker compose up`.
