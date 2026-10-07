# Scripts

| Script | Purpose |
|---|---|
| `smoke_test.sh` | Checks a running stack end to end: health, metrics, the dashboard's session guard and CSRF check. With `ADMIN_PASSWORD` it also logs in, waits for engine traffic, injects a simulated DDoS and checks the alert comes from the trained model, and verifies the audit log is append-only for the app's database role. With `MAILPIT_URL` (mail profile) it checks the alert email arrives. Used by CI. |
| `benchmark_stack.py` | Measures a running stack: alert-engine ingestion rate, API latency of the dashboard's endpoints, and detection-to-alert latency. Resolves open DDoS alerts on the simulator's web server between trials, so use a test stack. Results: [`docs/PERFORMANCE.md`](../docs/PERFORMANCE.md). |

Model training and the in-process engine benchmark are package commands:
`python -m argus_ml train` (see `ml/README.md`) and
`python -m argus_engine bench` (see `engine/README.md`).
