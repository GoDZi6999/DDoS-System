# ArgusAI — Phase 1 Architecture

Real-Time AI-Powered Network Threat Detection & SOC Platform.
Status: **approved** (2026-10-03). Implementation progress is tracked in the root README.

**Claim scope.** ArgusAI *detects and classifies suspicious network traffic in real time and raises risk-scored alerts*. It does not claim to prevent DDoS. Mitigation is a future, opt-in, safeguarded phase (§11).

## 0. Findings on the existing prototype

The current root-level Flask app trains on NSL-KDD (`data_preprocessing.py`, `model_training.py`) and runs a Scapy detector (`real_time_detection.py`).

| Issue | Consequence | Resolution |
|---|---|---|
| NSL-KDD features (`hot`, `logged_in`, `num_compromised`, `service`) cannot be derived from raw packets; live code approximates them | Train/serve skew — live predictions are unreliable | Train on **flow-level features** a flow meter can compute identically live and offline (CIC-style). One shared feature module used by both training and inference |
| Hard-coded label/service maps duplicated in training and live code | Silent preprocessing drift | Single `feature_config.json` + one `FeaturePipeline` class, versioned with the model |
| In-process queue, Flask-SocketIO, open dashboard, `SECRET_KEY` default | No auth, no persistence, not horizontally separable | FastAPI + Redis + PostgreSQL + JWT/RBAC |
| NSL-KDD (1999 traffic) | Weak real-world relevance | CIC-IDS2017 / CIC-DDoS2019 primary; UNSW-NB15 for cross-dataset generalisation check |

The prototype is retained under `legacy/` for reference only; ArgusAI superseded it in Phase 4 and nothing uses it.

## 1. System architecture

```
 Live iface ─┐                                   ┌──────────────┐
             ├─► Collector ─► Flow Builder ─────►│ Redis Stream │ flows
 PCAP replay ┘   (Scapy)      (5-tuple, timeouts)└──────┬───────┘
                                                        ▼
                                             ┌─────────────────────┐
                                             │ ML Engine worker(s) │
                                             │ FeaturePipeline →   │
                                             │ model → SHAP →      │
                                             │ Risk Engine         │
                                             └──────────┬──────────┘
                                                        ▼
                                  ┌─────────────── Redis Stream "detections"
                                  ▼                       ▼
                         FastAPI backend ◄──────── persist consumer ──► PostgreSQL
                         REST + WebSocket                 │
                                  │                       └─► Alert dispatcher (email/Slack/webhook)
                                  ▼
                           Next.js SOC dashboard
```

Design principles:
1. **Decoupled by streams.** Collector, ML engine, and API only talk through Redis Streams (consumer groups → back-pressure, replay, at-least-once).
2. **API never does packet/ML work.** It serves REST/WS and enforces authN/authZ.
3. **One feature definition** shared by training and inference.
4. **Explicit decision pipeline**: classify → explain → score → alert. Each stage is a separate, testable function.
5. **Safe by default**: capture is read-only; simulator targets only loopback/virtual lab network.

## 2. Component architecture

| Component | Responsibility | Tech |
|---|---|---|
| `engine` (sources) | Sniff an interface or replay a PCAP (speed factor, retimed), or run the safe simulator | Scapy (AsyncSniffer / PcapReader) |
| `engine` (flow builder) | Aggregate packets to bidirectional flows by 5-tuple; RST/FIN, idle and active timeouts; CICFlowMeter-style features | Python |
| `sentinel_ml.features` | Flow → fixed feature vector (shared with training) | Python package in `ml/` |
| `engine` (classifier + rules) | Versioned model bundle → class, probability, SHAP top-5; window rule for port scans | scikit-learn, XGBoost, SHAP |
| `engine` (risk) | Combine signals into 0–100 score; baseline frozen during attacks | Pure Python, weights from the settings API via Redis |
| `alert_service` | Dedupe/aggregate detections into alerts; state machine; notifications | FastAPI service module + Redis |
| `api` | REST, WebSocket, JWT, RBAC, audit | FastAPI, SQLAlchemy 2, Alembic |
| `capture-worker` | Analyse uploaded `.pcap`/`.pcapng` files: replay through the engine pipeline at full speed, report, tag detections with the capture id; cut alert packets out as evidence | asyncio worker (backend image) + `sentinel_engine` + Scapy |
| `notifier` | Alert notifications (email, Slack, webhook) from a transactional outbox; data retention | asyncio worker + PostgreSQL (`SKIP LOCKED`) |
| `frontend` | SOC dashboard | Next.js, Tailwind, Recharts |
| `engine` (simulator) | Benign + attack traffic for demos, in-process (sends nothing); attack statistics from held-out CIC-IDS2017 flows | Python |

**Alert aggregation:** a flood produces thousands of flow detections. Alerts are keyed by `(attack_type, dst_ip, time_window)`; detections attach to an open alert and update its counters, peak pps/bps, and max risk. Prevents alert storms and keeps the DB small.

## 3. ML pipeline

```
raw dataset ─► clean ─► label map ─► feature engineering ─► split ─► train ─► evaluate ─► select ─► bundle
```

- **Datasets:** CIC-IDS2017 + CIC-DDoS2019 (train/test), UNSW-NB15 (external generalisation). Labels collapsed to `benign | ddos | portscan | botnet | other_dos` (configurable).
- **Cleaning:** drop inf/NaN, dedupe, remove identifier columns (IPs, ports-as-ID, timestamps) to avoid leakage; **time/session-aware split** (not random row split — CIC flows from the same attack are near-duplicates and random splits inflate scores).
- **Features (live-computable):** duration, fwd/bwd packets & bytes, packets/s, bytes/s, mean/std/max/min packet length, IAT mean/std/max, SYN/ACK/FIN/RST/PSH counts and ratios, init window sizes, protocol, dst port class, plus *window-level* features (unique sources per dst, flows/s to dst) for source diversity.
- **Models:** Logistic Regression (baseline), Random Forest, XGBoost. Stratified k-fold CV, class weights / SMOTE only inside CV folds.
- **Metrics:** confusion matrix, precision/recall/F1 (per class + macro), ROC-AUC (OvR), PR-AUC, inference latency, feature importance. Report cross-dataset results honestly.
- **Selection:** best macro-F1 subject to a latency budget; recall on attack classes weighted over accuracy.
- **Explainability:** `shap.TreeExplainer` for tree models; top-5 signed contributions per prediction, normalised to % of total |SHAP|.
- **Bundle (versioned directory `models/<name>/<version>/`):**
  `model.joblib` (Pipeline: shared preprocessing + estimator, so there is no separate scaler file to drift), `background.joblib` (SHAP background), `feature_config.json`, `model_metadata.json` (dataset hash, git SHA, params, metrics, trained_at, library versions, artefact checksums). Implemented in Phase 4; results in [`ML_METHODOLOGY.md`](ML_METHODOLOGY.md).
- **Anti-skew rule:** preprocessing lives in `FeaturePipeline` (fit at train, serialized with the model, imported unchanged by `ml_engine`). A test asserts feature vectors from the same PCAP are identical via the offline and online paths.
- **Output contract:** `{label, confidence, class_probs, explanation[], model_version}` → "DDoS detected — confidence 97.4%".

## 4. Risk scoring

```
risk = round( w1·ml_confidence + w2·traffic_anomaly + w3·attack_severity + w4·source_reputation )
```
Default weights 0.40 / 0.25 / 0.25 / 0.10 (admin-configurable, audited).

| Signal | Definition (0–100) |
|---|---|
| ml_confidence | Probability of predicted attack class × 100 |
| traffic_anomaly | Robust z-score of pps/bps/flow-rate vs. rolling per-destination baseline (EWMA + MAD), squashed to 0–100 |
| attack_severity | Lookup by class (DDoS 90, botnet 80, portscan 50, …) × scaling by volume |
| source_reputation | Local history (prior alerts from the IP/subnet, repeat offender), optional allow/deny lists; no external feed required |

Bands: 0–30 LOW, 31–60 MEDIUM, 61–80 HIGH, 81–100 CRITICAL. Benign predictions skip the engine (risk 0). Every score stores its four components so analysts can see *why* it was 94.

## 5. Alert lifecycle & SOC workflow

```
NEW → INVESTIGATING → CONTAINED → RESOLVED     (+ FALSE_POSITIVE from any open state)
```
- Allowed transitions enforced server-side; each transition requires a role (Analyst+) and writes an audit entry plus an optional note.
- "Acknowledge" = NEW→INVESTIGATING with `acknowledged_by/at`.
- Notifications (Phase 7): dashboard (WebSocket) plus admin-configured channels (email via SMTP, Slack incoming webhook, generic HMAC-signed webhook). The alert engine writes a `notification_deliveries` row in the **same transaction** that creates or escalates an alert (transactional outbox), so a notification exists exactly when the alert change commits. Each channel has a minimum severity, hears about an alert **once per severity band** (a flood updating one alert sends at most four messages), and has a per-hour cap beyond which deliveries are recorded as `suppressed`. The `notifier` worker sends deliveries with `SELECT … FOR UPDATE SKIP LOCKED` (safe with several replicas), retries transient failures with backoff (30 s, 2 min, 10 min, 30 min; 5 attempts) and records every outcome; 4xx answers and private-address targets fail permanently.
- "Recommended action" is text derived from class + severity (playbook table); **advisory only**.

## 6. Database schema (PostgreSQL)

Implemented in Phase 3 (migration `backend/alembic/versions/0001_initial_schema.py`):

```
users(id, username UNIQUE, email UNIQUE, password_hash, role, is_active, token_version,
      created_at, updated_at, last_login_at)
refresh_tokens(id, user_id FK, token_hash UNIQUE, family_id, created_at, expires_at, revoked_at)
network_events(id, stream_id UNIQUE, ts, src_ip INET, dst_ip INET, src_port, dst_port, protocol,
               packet_count, byte_count, duration, packets_per_sec, bytes_per_sec,
               features JSONB, source)                      -- source: live | pcap | sim
predictions(id, event_id FK UNIQUE, model_version, label, confidence, class_probs JSONB,
            explanation JSONB, risk_score, risk_components JSONB, severity, created_at)
alerts(id, created_at, updated_at, first_seen_at, last_seen_at, attack_type, source_ip,
       destination_ip, destination_port, protocol, confidence, risk_score, severity, status,
       description, recommended_action, detection_count, peak_packets_per_sec,
       peak_bytes_per_sec, explanation JSONB, risk_components JSONB, model_version,
       assigned_to_id FK, acknowledged_by_id FK, acknowledged_at, resolved_at)
alert_events(alert_id FK, event_id FK)                     -- aggregation link
alert_notes(id, alert_id FK, author_id FK, body, created_at)
audit_logs(id, ts, actor_id FK, actor, action, entity_type, entity_id,
           before JSONB, after JSONB, ip INET, user_agent)
settings(key, value JSONB, updated_by_id FK, updated_at)   -- detection thresholds, risk weights
notification_channels(id, name UNIQUE, kind, enabled, min_severity, max_per_hour,
       config JSONB, created_by_id FK, created_at, updated_at)       -- Phase 7 (migration 0002)
notification_deliveries(id, channel_id FK, alert_id FK, event, dedupe_key, status,
       attempts, next_attempt_at, last_error, payload JSONB, created_at, sent_at)
       UNIQUE (channel_id, dedupe_key)                               -- one per alert severity band
```
Planned: `models` (Phase 4 registry; `predictions.model_version` then references it) and `attack_statistics` (Phase 7 rollups, only if stats on the raw tables get slow). Application logs go to container stdout rather than a `system_logs` table.

Indexes: `alerts(status, last_seen_at)`, `alerts(attack_type, destination_ip, status)` for correlation, `network_events(ts)`, `network_events(dst_ip, ts)`, `predictions(label)`, `audit_logs(ts)`, `audit_logs(entity_type, entity_id)`. Retention (Phase 7, run by the notifier every 6 h and by `python -m app.cli purge`): flows older than `EVENT_RETENTION_DAYS` (14) are deleted unless they are evidence for an alert that is open or was closed within `EVIDENCE_RETENTION_DAYS` (90); finished deliveries are kept `DELIVERY_RETENTION_DAYS` (30); alerts, notes and the audit log are never purged. Day partitioning would replace batched deletes if volumes require it. `audit_logs` is append-only: a trigger rejects UPDATE, DELETE and TRUNCATE, and the API connects as a non-owner role that cannot disable it.

## 7. API specification (FastAPI, `/api/v1`, OpenAPI at `/docs`)

| Group | Endpoints | Min role |
|---|---|---|
| Auth | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password` | public / any |
| Users | `GET/POST /users`, `GET/PATCH /users/{id}` (users are deactivated, never deleted) | Admin |
| Alerts | `GET /alerts` (filter: status, severity, type, ip, time; paginated), `GET /alerts/{id}`, `GET /alerts/{id}/events`, `PATCH /alerts/{id}/status`, `POST /alerts/{id}/notes`, `POST /alerts/{id}/ack`, `PUT /alerts/{id}/assignee` | Viewer read; Analyst write |
| Events | `GET /events`, `GET /events/{id}` (with prediction + SHAP) | Viewer |
| Stats | `GET /stats/summary` (events, attacks, blocked/contained, current risk), `GET /stats/timeseries`, `GET /stats/distribution` | Viewer |
| Detection | `GET/PUT /config/detection` (threshold, window, risk weights); planned: `POST /detect`, `GET /models`, `POST /models/{id}/activate` (Phase 4/5) | Analyst read / Admin write |
| Ingest control | Engine CLI for now (`python -m sentinel_engine run|inject`, see `engine/README.md`); API control endpoints deferred | Admin |
| Audit | `GET /audit` | Admin |
| Ops | `GET /health`, `GET /health/ready`, `GET /metrics` (Prometheus) | internal |
| Realtime | `WS /api/v1/ws`, authenticated by its first message (no token in the URL) — `alert.new`, `alert.updated`; planned: `stats.tick`, `traffic.tick` (Phase 5) | Viewer |

Conventions: JSON, ISO-8601 timestamps (a timezone is required on input), limit/offset pagination returning `{items, total, limit, offset}`, errors as FastAPI's `{"detail": ...}`. Full reference: [`API.md`](API.md).

## 8. Frontend architecture (Next.js App Router + Tailwind + Recharts)

```
app/
  (auth)/login
  (dashboard)/            # SOC overview: KPI cards, live traffic/attack chart,
                          #   recent alerts, attack distribution, risk gauge
  alerts/                 # table with filters; alerts/[id] detail:
                          #   fields + SHAP contribution bars + risk breakdown + timeline/notes + status actions
  events/  models/  audit/  settings/  users/
lib/api.ts  lib/ws.ts (reconnecting WS client)  lib/auth.ts
components/  hooks/useLiveAlerts  state: TanStack Query + WS-driven cache updates
```
No mock data in production code: every widget reads from the API/WS. The demo story is driven by the engine (`ENGINE_SCENARIO=demo`), not by the dashboard. Route guards by role. The API issues bearer tokens; the dashboard keeps them server-side in httpOnly cookies through a Next.js backend-for-frontend layer (`/api/backend` proxy, `/api/live` SSE relay of the WebSocket), so browser JavaScript never holds them.

## 9. Security architecture

**Authentication/authorisation:** argon2id password hashes; 15-minute HS256 access JWT carrying a per-user token version (bumped on password change, deactivation or token theft) + 7-day rotating refresh tokens stored as SHA-256 digests, with reuse detection that ends the whole session family; role and active status re-read from the database on every request; RBAC dependency on every route (Admin / Analyst / Viewer); failed-login throttling per username and per IP in Redis; the WebSocket authenticates with its first message. Details: [`SECURITY.md`](SECURITY.md).
**Audit:** middleware + service-level hooks log login/logout, status changes, acknowledgements, config changes, user management, model activation, PCAP/simulator control; entries are append-only and include actor, before/after, IP.
**Hardening:** secrets only via env (`.env.example`, no defaults for JWT secret in prod), strict CORS, security headers, Pydantic validation, parameterised SQL, upload limits + PCAP size/type checks, CSP on frontend, dependency scanning in CI.
**Capture privilege:** only the collector container gets `NET_RAW`/`NET_ADMIN`; it has no DB credentials.
**Privacy:** store headers/derived features only — never payloads.

### Threat model (STRIDE summary)
| Threat | Example | Control |
|---|---|---|
| Spoofing | Stolen/forged JWT | Short TTL, signature + issuer/audience checks, refresh rotation with reuse detection, BFF-held httpOnly cookies |
| Tampering | Analyst edits audit log; poisoned PCAP | Append-only audit table; PCAP parsed in sandboxed worker with limits |
| Repudiation | "I didn't resolve that alert" | Audit log with actor/IP |
| Info disclosure | Viewer reads config/users | RBAC per route; field-level filtering |
| DoS (on the platform itself) | Flood of flows overwhelms the pipeline | Redis stream max length, flow-table cap, API rate limits, worker back-pressure |
| Elevation | Analyst becomes admin | Role changes Admin-only + audited |
| ML-specific | Evasion / adversarial traffic, data poisoning | Documented limitation; model bundles are hash-verified; only Admin activates models |

## 10. Docker architecture

```
docker compose up
  db            postgres:16          volume pgdata; least-privilege app role created on init
  redis         redis:7              detection stream, pub/sub, detection-config mirror
  migrate       backend image        one-shot: alembic upgrade + first admin (schema owner)
  backend       FastAPI (uvicorn)    REST + WebSocket; trusts X-Forwarded-For only from frontend
  alert-engine  backend image        detections -> events, alerts, notification outbox
  notifier      backend image        sends notifications (retries), applies retention
  engine        sentinel_engine      simulator by default; PCAP replay / live capture options
  frontend      Next.js (standalone) dashboard + backend-for-frontend; fixed IP 172.28.0.10
  mailpit       (profile "mail")     local SMTP catcher for testing email notifications
```
Networks: `frontnet` (browser-facing: frontend, backend), `corenet` (internal, no egress: db, redis, workers, engine), `egressnet` (notifier and mail catcher, for SMTP/webhook traffic). The migrate step creates the first admin from env vars, and the trained model bundle ships in the repo, so a fresh clone demos without downloading datasets. The original Celery plan was dropped: the outbox in PostgreSQL gives durable queuing of exactly one delivery per (channel, alert band) without another broker, and matches the alert engine's asyncio worker pattern. Sending is at-least-once: a crash between a successful send and its commit can repeat one message.

## 11. Folder structure

```
backend/        app/{api,core,db,models,schemas,services,workers}, alembic/, tests/
frontend/       app/ (routes, BFF route handlers), components/, lib/, e2e/ (Playwright), proxy.ts
ml/             sentinel_ml: features, data, models, train, evaluate, explain, bundle, inference; reports/
engine/         sentinel_engine: packets, flows, window rule, risk, pipeline, simulator, sources, bench
data/           README (dataset download/cite), samples/flow_profiles.csv   # raw data gitignored
models/         sentinel-flow/<version>/ (bundle + checksums, committed)
infrastructure/ db/init, prometheus/, grafana/   # each service's Dockerfile lives in its own folder
tests/          README mapping the per-component test suites
docs/           ARCHITECTURE, API, ML_METHODOLOGY, SECURITY, PERFORMANCE, TESTING, DEMO, schemas/, images/
scripts/        smoke_test.sh, benchmark_stack.py
legacy/         NSL-KDD prototype (superseded, reference only)
.env.example  README.md  docker-compose.yml  .gitignore
```

## 12. Development roadmap

| Phase | Deliverable | Exit criteria |
|---|---|---|
| 1 | This document | Reviewed/approved |
| 2 | Repo skeleton, compose with db/redis/backend stub, `.env.example`, CI (lint, pytest) | `docker compose up` healthy |
| 3 | Backend: auth/RBAC → DB/migrations → alerts API + state machine → audit → WS | Every endpoint tested (pytest), RBAC matrix tested |
| 4 | ML: dataset prep, `sentinel_features`, 3 models, CV, metrics report, SHAP, bundle, inference service | Metrics report committed; offline/online feature parity test passes |
| 5 | Real-time: collector → flow builder → ML → risk → Redis → WS; PCAP replay; simulator | Replay demo raises CRITICAL alert end-to-end; p95 latency measured |
| 6 | Dashboard on real API/WS, detail page with SHAP, workflow actions | Playwright E2E: login → live alert → ack → resolve |
| 7 | Notifications (email/Slack/webhook) via transactional outbox + notifier worker, retention | Delivery logged + retried; email verified end to end in CI |
| 8 | Docs, screenshots, performance, limitations; optional Prometheus/Grafana | Fresh-clone `docker compose up` demo (verified: smoke test and Playwright pass on a default-config clone) |
| 9 (optional) | Policy engine + **dry-run** mitigation with allow-lists, rate caps, human approval | Only after validated false-positive rate |

## 13. Key risks & decisions

1. **Dataset size/licensing:** CIC datasets are tens of GB and must be downloaded by the user; the repo ships only a small sample + a pretrained demo model. *Decision:* train on a documented subset by default.
2. **Live vs. dataset distribution shift:** models trained on CIC capture conditions may misfire on a home network. *Mitigation:* feature set restricted to live-computable flow stats, cross-dataset eval, and a PCAP-replay + simulator test in the demo.
3. **Flow-meter choice:** custom Scapy flow builder (full control, slower) vs. CICFlowMeter (feature-compatible, Java). *Decided:* Scapy builder replicating the CIC feature definitions; validate against CICFlowMeter on a sample PCAP.
4. **Scope:** Prometheus/Grafana and mitigation are stage-later items; core value is Phases 3–6. *Decided (Phase 7):* no Celery; an asyncio notifier over a PostgreSQL outbox.
5. **Naming:** repo is `DDoS-System`; *Decided:* product name **ArgusAI**.

## 14. Limitations (to be stated in README)
Detection quality is bounded by training data; encrypted/application-layer attacks are only visible via flow statistics; Scapy throughput limits line-rate capture (suitable for lab/small networks); SHAP explains the model, not ground-truth causality; no prevention is claimed.
