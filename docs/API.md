# ArgusAI API

Base path `/api/v1` for the dashboard and people; `/v2` is the
[customer API](#customer-api-v2) for applications, authenticated with API keys. Interactive documentation (Swagger UI, generated from the
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
| `PUT /config/detection`, `/users*`, `GET /audit`, `/notifications/*` | | | ✓ |
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
`recommended_action` is advisory text; ArgusAI does not block traffic.

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
| `GET /alerts/{id}` | Adds `recommended_action`, `explanation` (SHAP factors), `risk_components`, `unique_sources`, `allowed_transitions`, `notes`, `history`, `wireshark_filter` (a display filter for the alert's traffic) and `evidence_capture_id` (the uploaded capture holding its packets, or `null`). |
| `GET /alerts/{id}/events` | The detections aggregated into the alert. |
| `GET /alerts/{id}/evidence.pcap` | Analyst. The alert's packets as a pcap file for Wireshark, cut from the uploaded capture with its original timestamps (at most 50,000 packets; `X-Evidence-Packets`, `X-Evidence-Truncated`). `422` for alerts not raised from an uploaded capture. Audited as `alert.evidence_downloaded`. |
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
| `GET /sensors` | Viewer. Capture sensors with `status` (`online`: reported within 15 s, `stale`: within 60 s, `offline`), host, interface, packet rate, flows sent/buffered/dropped and capture drops; plus `backlog` (`pending`, `lag`) of the engine on the sensor flow stream, `null` until the engine reads it. |
| `GET /audit` | Newest first. Filters: `actor`, `action`, `entity_type`, `entity_id`, `since`, `until`. Read-only by design. |

Audited actions: `auth.login`, `auth.login_failed`, `auth.locked`,
`auth.logout`, `auth.password_changed`, `auth.refresh_reuse_detected`,
`user.created`, `user.updated`, `alert.created`, `alert.escalated`,
`alert.acknowledged`, `alert.status_changed`, `alert.note_added`,
`alert.assigned`, `config.updated`, `notification.channel_created`,
`notification.channel_updated`, `notification.test_sent`, `retention.purged`,
`api_key.created`, `api_key.revoked`, `capture.uploaded`, `capture.deleted`,
`alert.evidence_downloaded`.

## Notifications

Admins configure where alerts are sent. Each channel has a minimum severity
and receives a message when an alert first reaches that severity and again
each time it escalates to a higher band: **at most one message per channel,
alert and severity band**, however many detections the alert absorbs.
Beyond `max_per_hour` messages per channel, further deliveries are recorded
as `suppressed`. Messages are advisory and link to the alert in the dashboard
(`DASHBOARD_URL`).

| Endpoint | Notes |
|---|---|
| `GET /notifications/channels` | All channels; secrets are masked (Slack URL path hidden, webhook query hidden, `secret_set` instead of the secret). Includes the last delivery's time and status. |
| `POST /notifications/channels` | `{"name", "kind", "min_severity": "HIGH", "max_per_hour": 30, "enabled": true, "config": {...}}` → `201`. |
| `GET /notifications/channels/{id}` | One channel (masked). |
| `PATCH /notifications/channels/{id}` | Fields sent are changed. Channels are disabled (`"enabled": false`), not deleted, so the delivery log keeps them. |
| `POST /notifications/channels/{id}/test` | Queues a test message → `202 {"delivery_id"}`; the outcome appears in the delivery log. |
| `GET /notifications/deliveries` | Newest first. Filters: `channel_id`, `alert_id`, `status` (repeatable: `pending`, `sent`, `failed`, `suppressed`). |

Channel `config` by `kind`:

| Kind | Config | Notes |
|---|---|---|
| `email` | `{"recipients": ["soc@example.com"]}` (1–20) | Sent through the SMTP relay in `SMTP_*` settings. |
| `slack` | `{"webhook_url": "https://hooks.slack.com/services/…"}` | Slack incoming webhook; message with fields and a link. |
| `webhook` | `{"url": "https://…", "secret": "16+ chars"}` | JSON POST. Omitting `secret` in a PATCH keeps the stored one; `null` removes it. |

Webhook requests carry `X-Sentinel-Event` (`alert.created`, `alert.escalated`,
`test`), `X-Sentinel-Delivery` (id, stable across retries, so receivers can
de-duplicate), `X-Sentinel-Timestamp` and, with a secret,
`X-Sentinel-Signature: sha256=<hex>`, the HMAC-SHA256 of
`"<timestamp>.<raw body>"`. Receivers should verify it with a constant-time
comparison and reject old timestamps. Body:

```json
{"delivery_id": 12, "event": "alert.created", "url": "http://localhost:3000/alerts/7",
 "alert": {"id": 7, "severity": "CRITICAL", "attack_type": "ddos", "description": "DDoS detected — …",
           "source_ip": "198.51.100.23", "destination_ip": "10.20.0.10", "destination_port": 80,
           "protocol": "tcp", "risk_score": 93, "confidence": 1.0, "detection_count": 12,
           "first_seen_at": "2026-10-04T05:53:19+00:00", "recommended_action": "…"}}
```

Webhook and Slack URLs must be `https` and resolve to public addresses
(private, loopback and link-local targets are refused) unless
`NOTIFY_ALLOW_PRIVATE_TARGETS=true`. Redirects are not followed. Failed
attempts are retried after 30 s, 2 min, 10 min and 30 min (5 attempts);
`4xx` answers (except 408/425/429), refused recipients and refused targets
fail at once. The reason is stored in `last_error`.

## Packet captures

Upload a capture saved by Wireshark or tcpdump (`.pcap` or `.pcapng`, up to
`CAPTURE_MAX_MB`, default 100) and the capture worker replays it through the
real-time engine at full speed: the same flow builder, model, rules and risk
scoring as live traffic. Timestamps are shifted so the capture ends at
analysis time, which keeps its flows and alerts inside the dashboard's time
windows; reports and evidence files keep the original times.

| Endpoint | Notes |
|---|---|
| `POST /captures?filename=x.pcapng&raise_alerts=true` | Analyst. The file is the raw request body (`Content-Type: application/octet-stream`). Checked by its magic bytes (`422` otherwise); `413` above the size limit. `202` with the capture, `status: queued`. With `raise_alerts` (default), attacks found raise alerts and notifications like live traffic, and those alerts can serve their packets as evidence. Audited as `capture.uploaded`. |
| `GET /captures` | Viewer. Newest first, paginated. |
| `GET /captures/{id}` | Viewer. `status`: `queued`, `analyzing`, `done` or `failed` (with `error`). |
| `DELETE /captures/{id}` | Admin. Deletes the file; alerts and flows it produced stay, without packet evidence. `409` while it is being analysed. Audited as `capture.deleted`. |

```bash
curl -X POST "localhost:8000/api/v1/captures?filename=monday.pcapng" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @monday.pcapng
```

A finished capture's `report`:

```json
{
  "packets": 7492, "flows": 2342, "attacks": 2202,
  "attack_types": {"ddos": 2200, "portscan": 2},
  "detected_by": {"rule:flood-v1": 1600, "model": 600, "rule:portscan-v1": 2},
  "top_sources": [{"ip": "198.51.100.7", "detections": 215}],
  "top_targets": [{"target": "192.168.10.80:443", "detections": 1600}],
  "max_risk": 97,
  "first_packet_at": "2026-09-21T14:13:20.931653+00:00",
  "last_packet_at": "2026-09-21T14:14:07.996000+00:00",
  "duration_s": 47.064, "analysis_s": 4.0, "model_version": "sentinel-flow-2026.10.03"
}
```

`attacks` counts attack detections (flows the model flagged, plus rule hits
such as port scans), not alerts; `detected_by` splits them between the model
and the engine's cross-flow rules. Non-IP packets are skipped.
`python -m app.cli demo-capture demo.pcap` writes a synthetic capture (web
traffic, a port scan, an HTTP flood the model catches and a SYN flood only the
flood rule catches) to try it with.

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
  // {type: "traffic.tick", data: {ts, source_id, flows_per_s, packets_per_s, attacks, attacks_per_s, max_risk, active_flows}}
};
ws.onclose = (e) => { if (e.code === 4401) { /* refresh the token, reconnect */ } };
```

- The auth message must arrive within 5 seconds.
- Close code **4401**: authentication failed, or the access token expired
  (connections do not outlive their token).
- Notifications are best effort; after reconnecting, reload state over REST.

## Customer API (`/v2`)

For applications and services rather than people: authenticated with an API
key in the `X-API-Key` header, not a user login. Two endpoints, both taking a
batch of flow records:

| Endpoint | Scope | What it does |
|---|---|---|
| `POST /v2/detect` | `detect` | Classifies the flows now and returns a verdict per flow. Stateless: nothing is stored and no alert is raised. |
| `POST /v2/flows` | `ingest` | Queues the flows for the real-time engine (`202`), which scores risk and raises alerts, notifications and webhooks like any capture sensor. Needs an engine running with `--source sensor`. |

### Keys

Admins manage keys in `/api/v1/api-keys` (audited as `api_key.created` and
`api_key.revoked`):

```bash
curl -s -X POST localhost:8000/api/v1/api-keys -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name": "shop-backend", "scopes": ["detect"]}'
# {"id": 1, "name": "shop-backend", "prefix": "3f9a1c2e", "scopes": ["detect"], ...,
#  "key": "argus_3f9a1c2e_Qm9…"}   <- shown once; only its SHA-256 is stored
```

| Endpoint | Notes |
|---|---|
| `GET /api-keys` | Admin. Paginated; never returns the key or its hash. `last_used_at` is updated at most once a minute. |
| `POST /api-keys` | Admin. `name` (unique, letters, digits, space, `.`, `_`, `-`), `scopes`: `detect` and/or `ingest`. `201` with the key. |
| `POST /api-keys/{id}/revoke` | Admin. Takes effect on the next request. |

### Flow records

Both endpoints take `{"flows": [ ... ]}` with 1 to `API_MAX_FLOWS` (default
1000) records, in the same shape the capture sensor sends:

```json
{
  "src_ip": "198.51.100.7", "dst_ip": "10.0.0.5", "src_port": 40000, "dst_port": 80,
  "protocol": "tcp", "start": 1790000000.0, "end": 1790000001.2, "duration": 1.2,
  "packet_count": 14, "byte_count": 9120,
  "features": {"flow_duration_s": 1.2, "fwd_packets": 8, "...": 0.0}
}
```

`features` holds the model's flow statistics (the
`features` of `models/sentinel-flow/<version>/feature_config.json`, computed the way the sensor's
flow builder computes them). `/v2/detect` answers `422` naming any missing
feature. Times are Unix seconds; values must be finite.

### Detect response

```json
{
  "model_version": "sentinel-flow-2026.10.03",
  "attacks": 1,
  "results": [
    {"index": 0, "label": "ddos", "is_attack": true, "confidence": 0.998,
     "class_probs": {"benign": 0.001, "ddos": 0.998, "...": 0.0},
     "explanation": [{"feature": "fwd_pkt_len_max", "value": 5840.0, "contribution": 1.73, "weight": 31.2}],
     "recommended_action": "Rate-limit or block the source at the edge ..."}
  ]
}
```

`explanation` lists the top SHAP reasons for attack flows, for at most
`API_MAX_EXPLAINED` (default 20) attacks per request; others get `[]`.
`recommended_action` is advice from the response playbook; ArgusAI does not
block anything itself.

### Errors and limits

`401` missing, unknown or revoked key; `403` key lacks the scope; `413` more
than `API_MAX_FLOWS` flows; `422` invalid records; `429` more than
`API_RATE_PER_MINUTE` (default 600) requests in the current minute for that
key, with `Retry-After: 60`; `503` model or flow queue unavailable. The model
loads on the first `/v2/detect` call, which takes a few seconds.

## Detection stream (ML engine → alert engine)

Producers (the real-time engine in `engine/`; `python -m app.cli demo-detections`
for testing) append to the Redis stream **`sentinel:detections`**, one entry per
analysed flow, with a single field `data` containing JSON. The machine-readable
contract is [`schemas/detection.schema.json`](schemas/detection.schema.json):
the backend tests check it matches the model, the engine tests validate their
output against it.

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
  "model_version": "xgb-2026.10.1",
  "capture_id": null
}
```

Detection settings changed through `PUT /config/detection` are mirrored to
the Redis key `sentinel:config:detection`, where the engine reads its risk
weights.

Rules (`backend/app/schemas/detection.py`): unknown fields are rejected;
`protocol` ∈ `tcp|udp|icmp|other`; `source` ∈ `live|pcap|sim`; `label` matches
`[a-z0-9_]{1,32}` (`benign` never raises alerts); `confidence` 0–1;
`risk_score` 0–100; `capture_id` (optional) names the uploaded capture a
flow came from; `weight` is the feature's share of total |SHAP| in
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
| `docker compose exec -T backend python -m app.cli demo-capture - > demo.pcap` | Writes a synthetic capture to try the Captures page with (not real traffic). |
| `docker compose logs capture-worker` | Capture analysis progress and failures. |
| `docker compose exec backend python -m app.cli purge` | Applies the retention policy now (the notifier also runs it every 6 hours). |
| `docker compose logs notifier` | Delivery outcomes (ids, channel names and status; no secrets or URLs). |
