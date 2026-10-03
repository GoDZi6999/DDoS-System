# Scripts

| Script | Purpose |
|---|---|
| `smoke_test.sh` | Checks a running stack end to end: frontend -> backend -> PostgreSQL + Redis. With `ADMIN_PASSWORD` set it also logs in, sends synthetic detections through the alert engine, waits for the alert and verifies the audit log is append-only for the app's database role. Used by CI. |

Planned: `train.sh` (Phase 4), `replay_demo.sh` (Phase 5).
