# Performance

Measured on 2026-10-04 on a 4-core x86_64 VM with 15 GB RAM, Docker Compose,
default settings, model `argus-flow-2026.10.03`. Numbers vary by machine;
the commands below reproduce them.

## Summary

| Stage | Result |
|---|---|
| Engine classification (model + SHAP + risk), 1-second batches | **~9,500 flows/s** benign, **~10,400 flows/s** during a flood |
| Engine, one flow per call | p50 **4.7 ms** benign, **11.3 ms** attack (with explanation) |
| Alert engine (stream → PostgreSQL → alerts), one process | **~2,200–2,300 detections/s** (worst case: every detection is an attack on one target) |
| Detection-to-alert latency (flow ends → alert committed) | median **1.65 s** over 3 trials (max 1.66 s) |
| Dashboard API endpoints | p50 **9–20 ms**, p95 **13–27 ms** |

The binding constraint for a sustained flood is the alert engine (about a
quarter of the engine's classification rate per process). Packet capture with
Scapy, which is pure Python, comes before both and limits live capture to
lab-scale traffic; the simulator and PCAP replay bypass it.

## 1. Engine

```bash
python -m argus_engine bench            # PYTHONPATH=engine:ml from the repo root
```

Runs `Engine.handle_flows` (classification, SHAP, risk, detection building),
the same path every tick takes, on flows sampled from the held-out profiles,
with an in-memory publisher.

| Flow, one per call | p50 | p95 | p99 |
|---|---:|---:|---:|
| benign | 4.71 ms | 6.45 ms | 12.0 ms |
| ddos (explained) | 11.32 ms | 14.84 ms | 22.93 ms |

| Batches of 100 flows, attack share | Flows/s |
|---|---:|
| 0% | 9,491 |
| 10% | 5,289 |
| 100% (flood) | 10,430 |

**What changed in Phase 8.** SHAP costs about ten times a prediction. The
engine used to explain every attack flow, which capped a flood at **~950
flows/s**. It now explains at most 5 attack flows per (attack type,
destination) per second (`EXPLAIN_PER_TARGET_S`); the alert shows one
representative explanation, so nothing is lost for the analyst. The 10% mix
is the slowest case because its attack flows are spread over 20 targets and
many small explanation calls, each with fixed overhead.

## 2. Alert engine

```bash
ADMIN_PASSWORD=… python3 scripts/benchmark_stack.py
```

The script stops the alert engine, queues 5,000 synthetic detections (all
`ddos` against one target, so every one goes through correlation), restarts
it and times the backlog from the first stored event to the last.

| Version | Detections/s |
|---|---:|
| Phase 7 (one transaction per detection) | ~100 |
| Phase 8 (one transaction per stream read, bulk inserts, one lock and alert lookup per (type, target) per batch) | ~2,200–2,300 |

Each read takes up to 100 entries. Correlation rules are unchanged (see
`ingest_batch` in `backend/app/services/alerts.py` and its tests). Several
alert-engine replicas can share the consumer group
(`docker compose up --scale alert-engine=3`); detections for the same target
then serialise on that target's lock, so scaling helps most with many targets.

## 3. Detection-to-alert latency

Measured from the alert itself: `first_seen_at` (when the creating flow ended
in the engine) to its `alert.created` audit entry (when the transaction
committed). Three trials, each on a new alert: **1,655 / 1,650 / 1,568 ms**.
Most of it is the engine's 1-second tick: finished flows are classified and
published once per tick. Dashboards receive the alert over the WebSocket/SSE
relay immediately after the commit; email arrives within the notifier's
2-second poll plus SMTP time.

## 4. API

200 sequential requests per endpoint, after the benchmark had stored ~37,000
flows:

| Endpoint | p50 | p95 |
|---|---:|---:|
| `GET /alerts?limit=50` | 8.7 ms | 13.2 ms |
| `GET /alerts/{id}` | 13.0 ms | 17.1 ms |
| `GET /stats/summary?window=24h` | 20.4 ms | 27.4 ms |
| `GET /stats/timeseries?window=24h&bucket=15m` | 13.0 ms | 17.3 ms |
| `GET /stats/distribution?window=24h` | 11.8 ms | 15.6 ms |
| `GET /events?limit=50` | 15.1 ms | 20.2 ms |

Statistics are computed on the raw tables. They grow with the retention
window (14 days of flows by default). A planned optimisation, if they become
slow, is rollup tables or time partitioning; earlier runs on a database with
several floods' worth of detections showed `stats/summary` around 55–65 ms p50.

## Caveats

- One machine, one run per configuration; treat the numbers as orders of magnitude.
- The engine benchmark uses simulator flows (feature vectors from CIC-IDS2017);
  live capture adds packet parsing and flow assembly costs not measured here.
- The alert-engine figure is a worst case for correlation; benign detections
  skip correlation and are cheaper.
