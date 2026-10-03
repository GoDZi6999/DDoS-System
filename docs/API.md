# SentinelAI API

Base path `/api/v1`. Interactive documentation (Swagger UI, generated from the
code) is served at <http://localhost:8000/docs>; its **Authorize** button logs
in with the same OAuth2 password flow described below.

Conventions:

- JSON bodies; timestamps are ISO-8601 and **must include a timezone** on input
  (`2026-10-03T15:00:00Z`).
- Lists are paginated with `limit` (1–200, default 50) and `offset`, and return
  `{"items": [...], "total": n, "limit": 50, "offset": 0}`.
- Errors use FastAPI's format: `{"detail": "..."}` (validation errors carry a
  list). `401` = not authenticated, `403` = role too low, `404` = not found,
  `409` = conflicting state (e.g. invalid workflow transition), `422` = invalid
  input, `429` = login throttled (see `Retry-After`).

## Authentication

```bash
# 1. Log in (form fields, OAuth2 password flow)
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  --data-urlencode username=admin --data-urlencode 'password=…'
# {"access_token": "eyJ…", "token_type": "bearer", "expires_in": 899,
#  "refresh_token": "Xk3…", "refresh_expires_in": 604799}

# 2. Call the API with the access token
curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer eyJ…"
```

| Endpoint | Purpose |
|---|---|
| `POST /auth/login` | Form fields `username` (case-insensitive), `password`. Returns a token pair. |
| `POST /auth/refresh` | `{"refresh_token": "…"}` → new pair. Each refresh token works **once**; presenting an already-used one ends every session descended from that login. |
| `POST /auth/logout` | `{"refresh_token": "…"}` → revokes it (`204`, also for unknown tokens). |
| `GET /auth/me` | The current user. |
| `POST /auth/password` | `{"current_password", "new_password"}` → `204`; ends all of the user's sessions. |

Access tokens last 15 minutes and refresh tokens 7 days (configurable). Role
and active status are checked against the database on every request, so a
role change or deactivation applies immediately. After 5 failed logins for one
username (or 20 from one IP) within 15 minutes, logins are refused with `429`.
Passwords are 12–128 characters; there are no composition rules.

## Roles

Roles are hierarchical: **admin** ⊃ **analyst** ⊃ **viewer**. The full matrix
is enforced by `backend/tests/test_rbac.py`, which also fails if an endpoint
is added without being listed.

| Endpoints | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| `GET /alerts`, `/alerts/{id}`, `/alerts/{id}/events`, `/events`, `/events/{id}`, `/stats/*` | ✓ | ✓ | ✓ |
| `POST /alerts/{id}/ack`, `PATCH /alerts/{id}/status`, `POST /alerts/{id}/notes`, `PUT /alerts/{id}/assignee` | | ✓ | ✓ |
| `GET /config/detection` | | ✓ | ✓ |
| `PUT /config/detection`, `/users*`, `GET /audit` | | | ✓ |
| `WS /ws` | ✓ | ✓ | ✓ |

## Alerts

### How detections become alerts

The alert engine stores every detection as an event. A detection raises or
updates an alert when its label is not `benign` and its risk score is at
least `alert_min_risk` (default 31). Detections are correlated by
**(attack type, destination IP)**: an open alert (NEW, INVESTIGATING or
CONTAINED) for the same pair last seen within `aggregation_window_minutes`
(default 15) absorbs the detection, so a flood raises one alert, not
thousands. The highest-risk detection drives the alert's risk score,
severity, source IP and explanation; a jump to a higher severity band is
recorded as `alert.escalated`.

Severity bands: 0–30 LOW, 31–60 MEDIUM, 61–80 HIGH, 81–100 CRITICAL.
`recommended_action` is advisory text; SentinelAI does not block traffic.

### Workflow

Main path: `NEW → INVESTIGATING → CONTAINED → RESOLVED`, plus dismissal as
`FALSE_POSITIVE` and reopening:

| From | Allowed next states |
|---|---|
| NEW | INVESTIGATING, FALSE_POSITIVE |
| INVESTIGATING | CONTAINED, RESOLVED, FALSE_POSITIVE |
| CONTAINED | INVESTIGATING, RESOLVED |
| RESOLVED, FALSE_POSITIVE | INVESTIGATING (reopen) |

The detail response lists `allowed_transitions` for the current state. The
first move out of NEW records `acknowledged_by`/`acknowledged_at`; closing sets
`resolved_at`; reopening clears it. A closed alert never absorbs new
detections: the next one starts a new alert. Every change is audited and
appears in the alert's `history`.

### Endpoints

| Endpoint | Notes |
|---|---|
| `GET /alerts` | Filters: `status` (repeatable), `severity` (repeatable), `attack_type`, `ip` (source or destination), `since`, `until`; `sort=last_seen` (default) or `risk`. |
| `GET /alerts/{id}` | Adds `recommended_action`, `explanation` (SHAP factors), `risk_components`, `unique_sources`, `allowed_transitions`, `notes`, `history`. |
| `GET /alerts/{id}/events` | The detections aggregated into the alert. |
| `POST /alerts/{id}/ack` | NEW → INVESTIGATING; `409` if already acknowledged. |
| `PATCH /alerts/{id}/status` | `{"status": "CONTAINED", "note": "optional"}`; `409` for an invalid transition. |
| `POST /alerts/{id}/notes` | `{"body": "…"}` (1–5000 characters). |
| `PUT /alerts/{id}/assignee` | `{"user_id": 3}` or `{"user_id": null}`; the assignee must be an active analyst or admin. |

Example alert (list item):

```json
{
  "id": 1, "status": "NEW", "severity": "CRITICAL", "attack_type": "ddos",
  "source_ip": "198.51.100.96", "destination_ip": "203.0.113.65", "destination_port": 80,
  "protocol": "tcp", "confidence": 0.99, "risk_score": 95, "detection_count": 10,
  "first_seen_at": "2026-10-03T15:52:06.210444Z", "last_seen_at": "2026-10-03T15:52:15.257402Z",
  "peak_packets_per_sec": 49963.0, "peak_bytes_per_sec": 2997780.4,
  "description": "DDoS detected — confidence 99.0% — target 203.0.113.65:80",
  "assigned_to": null
}
```

## Events, statistics, settings, audit

| Endpoint | Notes |
|---|---|
| `GET /events` | Analysed flows with their prediction. Filters: `label`, `ip`, `since`, `until`, `min_risk`. |
| `GET /events/{id}` | Adds `features`, `class_probs`, `explanation`, `risk_components`, `model_version`, `alert_ids`. |
| `GET /stats/summary?window=24h` | `window`: `1h`, `6h`, `24h`, `7d`. Events and attacks in the window; current alert counts by status and (open) severity; highest open risk score. |
| `GET /stats/timeseries?window=24h&bucket=15m` | `bucket`: `1m`, `5m`, `15m`, `1h`, `6h`; empty buckets are filled; at most 1440 points. |
| `GET /stats/distribution?window=24h` | Flow counts per predicted label, `benign` included. |
| `GET /config/detection` / `PUT` | `{"alert_min_risk": 31, "aggregation_window_minutes": 15, "risk_weights": {"ml_confidence": 0.4, "traffic_anomaly": 0.25, "attack_severity": 0.25, "source_reputation": 0.1}}`; weights must sum to 1. Changes are audited with before/after values. |
| `GET /audit` | Newest first. Filters: `actor`, `action`, `entity_type`, `entity_id`, `since`, `until`. Read-only by design. |

Audited actions: `auth.login`, `auth.login_failed`, `auth.locked`,
`auth.logout`, `auth.password_changed`, `auth.refresh_reuse_detected`,
`user.created`, `user.updated`, `alert.created`, `alert.escalated`,
`alert.acknowledged`, `alert.status_changed`, `alert.note_added`,
`alert.assigned`, `config.updated`.

## Live updates (WebSocket)

`ws://localhost:8000/api/v1/ws`. The token goes in the first message, not the
URL, so it never appears in access logs.

```js
const ws = new WebSocket("ws://localhost:8000/api/v1/ws");
ws.onopen = () => ws.send(JSON.stringify({ type: "auth", token: accessToken }));
ws.onmessage = (msg) => {
  const event = JSON.parse(msg.data);
  // {type: "auth.ok", user: {...}}  then
  // {type: "alert.new" | "alert.updated", data: <alert list item>}
};
ws.onclose = (e) => { if (e.code === 4401) { /* refresh the token, reconnect */ } };
```

- The auth message must arrive within 5 seconds.
- Close code **4401**: authentication failed, or the access token expired
  (connections do not outlive their token).
- Notifications are best effort; after reconnecting, reload state over REST.

## Detection stream (ML engine → alert engine)

Producers (the Phase 5 ML engine; `python -m app.cli demo-detections` for
testing) append to the Redis stream **`sentinel:detections`**, one entry per
analysed flow, with a single field `data` containing JSON:

```json
{
  "ts": "2026-10-03T15:52:06Z",
  "src_ip": "198.51.100.7", "dst_ip": "203.0.113.10",
  "src_port": 40000, "dst_port": 80, "protocol": "tcp",
  "packet_count": 5000, "byte_count": 300000, "duration": 1.0,
  "packets_per_sec": 5000.0, "bytes_per_sec": 300000.0,
  "features": {"syn_ratio": 0.9},
  "source": "live",
  "label": "ddos", "confidence": 0.97, "class_probs": {"ddos": 0.97, "benign": 0.03},
  "explanation": [
    {"feature": "packets_per_sec", "value": 5000.0, "contribution": 0.4, "weight": 60.0}
  ],
  "risk_score": 85,
  "risk_components": {"ml_confidence": 97, "traffic_anomaly": 90},
  "model_version": "xgb-2026.10.1"
}
```

Rules (`backend/app/schemas/detection.py`): unknown fields are rejected;
`protocol` ∈ `tcp|udp|icmp|other`; `source` ∈ `live|pcap|sim`; `label` matches
`[a-z0-9_]{1,32}` (`benign` never raises alerts); `confidence` 0–1;
`risk_score` 0–100; `weight` is the feature's share of total |SHAP| in
percent; Infinity/NaN are rejected. Severity is derived from `risk_score` by
the alert engine.

Delivery is at-least-once through the consumer group `alert-engine`: an entry
is acknowledged after its transaction commits; the stream entry id is stored
with the event so a redelivery is not stored twice; invalid entries are moved
to `sentinel:detections:dead` with the validation error; entries left pending
by a crashed consumer are reclaimed after 60 seconds.

## Operational commands

| Command | Purpose |
|---|---|
| `docker compose logs migrate` | Shows the generated admin password after the first start (if `INITIAL_ADMIN_PASSWORD` was unset). |
| `docker compose exec backend python -m app.cli reset-password <user>` | Account recovery: prints a new generated password, ends the user's sessions, audits the reset. |
| `docker compose exec alert-engine python -m app.cli demo-detections --count 20` | Publishes synthetic, clearly labelled (`source: sim`, `model_version: synthetic-demo`) detections from documentation IP ranges, to exercise the pipeline before the ML engine exists. |
| `docker compose exec backend alembic current` | Shows the applied migration. |
