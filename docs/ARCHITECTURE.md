# SentinelAI — Phase 1 Architecture

Real-Time AI-Powered Network Threat Detection & SOC Platform.
Status: **approved** (2026-10-03). Implementation progress is tracked in the root README.

**Claim scope.** SentinelAI *detects and classifies suspicious network traffic in real time and raises risk-scored alerts*. It does not claim to prevent DDoS. Mitigation is a future, opt-in, safeguarded phase (§11).

## 0. Findings on the existing prototype

The current root-level Flask app trains on NSL-KDD (`data_preprocessing.py`, `model_training.py`) and runs a Scapy detector (`real_time_detection.py`).

| Issue | Consequence | Resolution |
|---|---|---|
| NSL-KDD features (`hot`, `logged_in`, `num_compromised`, `service`) cannot be derived from raw packets; live code approximates them | Train/serve skew — live predictions are unreliable | Train on **flow-level features** a flow meter can compute identically live and offline (CIC-style). One shared feature module used by both training and inference |
| Hard-coded label/service maps duplicated in training and live code | Silent preprocessing drift | Single `feature_config.json` + one `FeaturePipeline` class, versioned with the model |
| In-process queue, Flask-SocketIO, open dashboard, `SECRET_KEY` default | No auth, no persistence, not horizontally separable | FastAPI + Redis + PostgreSQL + JWT/RBAC |
| NSL-KDD (1999 traffic) | Weak real-world relevance | CIC-IDS2017 / CIC-DDoS2019 primary; UNSW-NB15 for cross-dataset generalisation check |

The prototype is retained under `legacy/` for reference and removed once Phase 4 reaches parity.

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
| `collector` | Sniff interface or replay PCAP (with speed factor); emit packet records | Scapy (AsyncSniffer / `rdpcap` iterator) |
| `flow_builder` | Aggregate packets to bidirectional flows by 5-tuple; idle/active timeouts; emit finished + periodic partial flows (so floods are seen *during* the attack) | Python, in-memory table with LRU cap |
| `feature_extractor` | Flow → fixed feature vector (shared with training) | Python package `sentinel_features` |
| `ml_engine` | Load versioned model bundle; predict class + probability; SHAP top-k; publish detection | scikit-learn, XGBoost, SHAP |
| `risk_engine` | Combine signals into 0–100 score and severity | Pure Python, config-driven weights |
| `alert_service` | Dedupe/aggregate detections into alerts; state machine; notifications | FastAPI service module + Redis |
| `api` | REST, WebSocket, JWT, RBAC, audit | FastAPI, SQLAlchemy 2, Alembic |
| `worker` | Notifications, retention, statistics rollups, retraining jobs | Celery + Redis |
| `frontend` | SOC dashboard | Next.js, Tailwind, Recharts |
| `simulator` | Benign + attack traffic generator for the lab | Scapy / pure-Python sockets on isolated Docker network |

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
- **Bundle (versioned directory `models/<name>/<semver>/`):**
  `model.pkl`, `scaler.pkl`, `feature_config.json`, `model_metadata.json` (dataset hash, git SHA, params, metrics, trained_at, library versions), `shap_background.pkl`.
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
- Notifications: dashboard (WebSocket), email (SMTP), Slack/Teams webhook. Rules: min severity per channel, rate-limited per alert. Delivery attempts logged.
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
```
Planned: `models` (Phase 4 registry; `predictions.model_version` then references it) and `attack_statistics` (Phase 7 rollups, only if stats on the raw tables get slow). Application logs go to container stdout rather than a `system_logs` table.

Indexes: `alerts(status, last_seen_at)`, `alerts(attack_type, destination_ip, status)` for correlation, `network_events(ts)`, `network_events(dst_ip, ts)`, `predictions(label)`, `audit_logs(ts)`, `audit_logs(entity_type, entity_id)`. Day partitioning and retention for `network_events`/`predictions` are planned for Phase 7. `audit_logs` is append-only: a trigger rejects UPDATE, DELETE and TRUNCATE, and the API connects as a non-owner role that cannot disable it.

## 7. API specification (FastAPI, `/api/v1`, OpenAPI at `/docs`)

| Group | Endpoints | Min role |
|---|---|---|
| Auth | `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/password` | public / any |
| Users | `GET/POST /users`, `GET/PATCH /users/{id}` (users are deactivated, never deleted) | Admin |
| Alerts | `GET /alerts` (filter: status, severity, type, ip, time; paginated), `GET /alerts/{id}`, `GET /alerts/{id}/events`, `PATCH /alerts/{id}/status`, `POST /alerts/{id}/notes`, `POST /alerts/{id}/ack`, `PUT /alerts/{id}/assignee` | Viewer read; Analyst write |
| Events | `GET /events`, `GET /events/{id}` (with prediction + SHAP) | Viewer |
| Stats | `GET /stats/summary` (events, attacks, blocked/contained, current risk), `GET /stats/timeseries`, `GET /stats/distribution` | Viewer |
| Detection | `GET/PUT /config/detection` (threshold, window, risk weights); planned: `POST /detect`, `GET /models`, `POST /models/{id}/activate` (Phase 4/5) | Analyst read / Admin write |
| Ingest control | planned (Phase 5): `POST /replay` (PCAP upload + speed), `POST /simulator/start|stop`, `GET /collector/status` | Admin |
| Audit | `GET /audit` | Admin |
| Ops | `GET /health`, `GET /health/ready`; planned: `GET /metrics` (Phase 8) | internal |
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
No mock data in production code: every widget reads from the API/WS. A `NEXT_PUBLIC_DEMO` mode only toggles the *simulator* on the backend. Route guards by role. The API issues bearer tokens; the dashboard will keep them server-side in httpOnly cookies through a Next.js backend-for-frontend layer, so browser JavaScript never holds them.

## 9. Security architecture

**Authentication/authorisation:** argon2id password hashes; 15-minute HS256 access JWT carrying a per-user token version (bumped on password change, deactivation or token theft) + 7-day rotating refresh tokens stored as SHA-256 digests, with reuse detection that ends the whole session family; role and active status re-read from the database on every request; RBAC dependency on every route (Admin / Analyst / Viewer); failed-login throttling per username and per IP in Redis; the WebSocket authenticates with its first message. Details: [`SECURITY.md`](SECURITY.md).
**Audit:** middleware + service-level hooks log login/logout, status changes, acknowledgements, config changes, user management, model activation, PCAP/simulator control; entries are append-only and include actor, before/after, IP.
**Hardening:** secrets only via env (`.env.example`, no defaults for JWT secret in prod), strict CORS, security headers, Pydantic validation, parameterised SQL, upload limits + PCAP size/type checks, CSP on frontend, dependency scanning in CI.
**Capture privilege:** only the collector container gets `NET_RAW`/`NET_ADMIN`; it has no DB credentials.
**Privacy:** store headers/derived features only — never payloads.

### Threat model (STRIDE summary)
| Threat | Example | Control |
|---|---|---|
| Spoofing | Stolen/forged JWT | Short TTL, signature + issuer/audience checks, refresh rotation with reuse detection, BFF-held httpOnly cookies (Phase 6) |
| Tampering | Analyst edits audit log; poisoned PCAP | Append-only audit table; PCAP parsed in sandboxed worker with limits |
| Repudiation | "I didn't resolve that alert" | Audit log with actor/IP |
| Info disclosure | Viewer reads config/users | RBAC per route; field-level filtering |
| DoS (on the platform itself) | Flood of flows overwhelms the pipeline | Redis stream max length, flow-table cap, API rate limits, worker back-pressure |
| Elevation | Analyst becomes admin | Role changes Admin-only + audited |
| ML-specific | Evasion / adversarial traffic, data poisoning | Documented limitation; model bundles are hash-verified; only Admin activates models |

## 10. Docker architecture

```
docker compose up
  db         postgres:16          volume pgdata, healthcheck
  redis      redis:7              streams + celery broker
  backend    FastAPI (uvicorn)    depends_on db, redis; runs alembic upgrade on start
  ml-engine  Python worker        mounts models/ read-only; consumes `flows`
  collector  Scapy                cap_add NET_RAW; profiles: live | replay
  worker     Celery               notifications, rollups
  simulator  Scapy/sockets        profile: demo; isolated network `labnet`
  frontend   Next.js (standalone)
  (optional profile) prometheus + grafana
```
Networks: `frontnet` (frontend↔backend), `corenet` (backend↔db↔redis↔ml), `labnet` (simulator↔collector, internal: true, no egress). A seed step creates default admin from env vars and loads a bundled demo model + small sample PCAP so a fresh clone demos without downloading large datasets.

## 11. Folder structure

```
backend/        app/{api,core,models,schemas,services,ws}, alembic/, tests/
frontend/       app/, components/, lib/, e2e/ (Playwright)
ml/             sentinel_features/ (shared), training/, evaluation/, inference/, notebooks/
collector/      capture.py, flow_builder.py, replay.py
simulator/      benign.py, attacks.py, scenarios/*.yaml
data/           README (dataset download/cite), samples/ (tiny PCAPs)   # raw data gitignored
models/         <name>/<version>/…                                      # large binaries gitignored; demo model tracked via LFS or script
infrastructure/ db/init, prometheus/, grafana/   # each service's Dockerfile lives in its own folder
tests/          integration/, e2e/, ml-regression/
docs/           ARCHITECTURE.md, API.md, ML_METHODOLOGY.md, THREAT_MODEL.md, TESTING.md, DEMO.md
scripts/        train.sh, seed.py, replay_demo.sh, fetch_datasets.sh
legacy/         current NSL-KDD prototype (temporary)
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
| 7 | Notifications (email/Slack/webhook), Celery rollups, retention | Delivery logged + retried |
| 8 | Docs, screenshots, performance, limitations; optional Prometheus/Grafana | Fresh-clone `docker compose up` demo |
| 9 (optional) | Policy engine + **dry-run** mitigation with allow-lists, rate caps, human approval | Only after validated false-positive rate |

## 13. Key risks & decisions

1. **Dataset size/licensing:** CIC datasets are tens of GB and must be downloaded by the user; the repo ships only a small sample + a pretrained demo model. *Decision:* train on a documented subset by default.
2. **Live vs. dataset distribution shift:** models trained on CIC capture conditions may misfire on a home network. *Mitigation:* feature set restricted to live-computable flow stats, cross-dataset eval, and a PCAP-replay + simulator test in the demo.
3. **Flow-meter choice:** custom Scapy flow builder (full control, slower) vs. CICFlowMeter (feature-compatible, Java). *Decided:* Scapy builder replicating the CIC feature definitions; validate against CICFlowMeter on a sample PCAP.
4. **Scope:** Celery, Prometheus/Grafana, and mitigation are stage-later items; core value is Phases 3–6.
5. **Naming:** repo is `DDoS-System`; *Decided:* product name **SentinelAI**.

## 14. Limitations (to be stated in README)
Detection quality is bounded by training data; encrypted/application-layer attacks are only visible via flow statistics; Scapy throughput limits line-rate capture (suitable for lab/small networks); SHAP explains the model, not ground-truth causality; no prevention is claimed.
