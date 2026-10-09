# Security controls

What ArgusAI implements today (all phases), how it is verified, and what is
still open. The threat model (STRIDE) is in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §9.

## Implemented

### Authentication

| Control | Detail | Verified by |
|---|---|---|
| Password storage | argon2id (pwdlib defaults: 64 MiB, 3 iterations); hashes upgraded on login if parameters change | `test_auth.py` |
| Password policy | 12–128 characters, no composition rules (NIST SP 800-63B); input over 128 characters is refused before hashing | `test_users.py`, `test_auth.py` |
| No user enumeration | Unknown user and wrong password give the same response; a dummy hash is verified for unknown users so timing matches | `test_wrong_password_and_unknown_user_look_identical` |
| Brute-force throttling | 5 failures per username or 20 per IP in 15 minutes → `429` with `Retry-After`; lockouts are audited once | `test_repeated_failures_lock_the_account` |
| Access tokens | HS256 JWT, 15 minutes, issuer and audience checked, `alg` pinned (rejects `none`), required claims enforced | `test_invalid_tokens_are_rejected` |
| Immediate revocation | Tokens carry a per-user version; password change, admin reset, deactivation and token theft bump it. Role and active status are re-read on every request | `test_deactivation_takes_effect_on_the_next_request` |
| Refresh tokens | 256-bit random, stored only as SHA-256 digests, single use (rotation), 7 days | `test_refresh_rotates_the_token_pair` |
| Theft detection | Replaying a rotated refresh token revokes its whole session family and all access tokens, and is audited | `test_replayed_refresh_token_ends_the_whole_session` |
| Signing key | `JWT_SECRET` (32+ chars) required when `ENVIRONMENT=production`; development generates a per-process key | `app/core/config.py` |

### Authorisation

- Three hierarchical roles (admin ⊃ analyst ⊃ viewer) enforced by a FastAPI
  dependency on every route.
- `test_rbac.py` calls every endpoint as every role and anonymously, and fails
  if a new endpoint is not in the matrix.
- At least one active admin always remains (demotion/deactivation of the last
  one returns `409`; concurrent requests are serialised with row locks).
- Users are deactivated, never deleted, so the audit trail keeps its referents.

### Audit trail

- Security-relevant actions are written in the same transaction as the action
  itself (logins, failures, lockouts, user changes, alert workflow, settings).
- **Tamper resistance in the database**: a trigger rejects UPDATE, DELETE and
  TRUNCATE on `audit_logs` for every role. The API and alert engine connect as
  `sentinel_app`, a non-owner, non-superuser role created by
  `infrastructure/db/init/01-app-role.sh`, which therefore cannot drop or
  disable the trigger. Migrations run as the schema owner in a separate
  one-shot container. Verified by `test_audit_log_rejects_updates_and_deletes`
  and by the CI smoke test, which tries `DELETE FROM audit_logs` as the app role.

### API and transport

- WebSocket tokens travel in the first message, never in the URL (URLs end up
  in access logs); connections close with `4401` when the token expires.
- Strict request schemas (`extra="forbid"`), timezone-aware timestamps
  required, IP addresses and enums validated; detections with Infinity/NaN are
  rejected.
- Security headers on every response (`X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`), plus
  `Cache-Control: no-store` and a restrictive CSP on `/api/*` and `/v2/*`.
- Customer API keys (`/v2`): random 256-bit secrets shown once; only their
  SHA-256 is stored, and lookups go by hash. Each key carries scopes
  (`detect`, `ingest`), is rate-limited per minute and capped in flows per
  request; admins create and revoke keys, and both are audited.
- Readiness probe reports only `ok`/`error`; failure details stay in logs.
- No CORS headers are sent: browsers cannot call the API cross-origin. The
  dashboard reaches it through a same-origin backend-for-frontend.

### Dashboard (backend-for-frontend)

| Control | Detail | Verified by |
|---|---|---|
| Tokens never reach the browser | Access and refresh tokens live in httpOnly, SameSite=Lax cookies set by the Next.js server; `Secure` with `COOKIE_SECURE=true` | `frontend/lib/session.ts` |
| Endpoint allowlist | `/api/backend/*` forwards only the endpoints the dashboard uses; anything else is `404` | smoke test (`401` without a session) |
| CSRF | Non-GET requests need `x-sentinel-csrf: 1` and a same-origin `Origin` (a cross-site form cannot set either); sign-in and sign-out are server actions, which Next.js checks for origin | smoke test (`403` without the header) |
| Session refresh without false theft alarms | Concurrent refreshes of one refresh token share a single API call, so parallel dashboard requests do not trip reuse detection | E2E |
| Open redirect | The post-login `next` parameter accepts same-site paths only | `app/actions.ts` |
| Page guard | `proxy.ts` sends requests without a session cookie to the login page; the API still validates every request | smoke test, E2E |
| Headers | CSP (`default-src 'self'`, `frame-ancestors 'none'`, `connect-src 'self'`, `form-action 'self'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` | `next.config.ts` |
| Request size | Proxied bodies are capped at 64 KB | route handler |
| Client IP | The API trusts `X-Forwarded-For` only from the dashboard container's fixed address (`FORWARDED_ALLOW_IPS`), so login throttling and audit entries see the browser's address | manual check of `audit_logs.ip` |

### Notifications

| Control | Detail | Verified by |
|---|---|---|
| Admin-only configuration | Channel management and the delivery log require the admin role; every change and test is audited, with secrets masked in the audit entry | `test_rbac.py`, `test_channel_secrets_are_masked_and_changes_audited` |
| Secrets never returned | Slack webhook paths, webhook query strings and signing secrets are masked in every API response; the worker logs delivery ids and channel names, never URLs | same |
| SSRF guard | Webhook/Slack targets must be `https` and resolve only to public addresses (loopback, private, link-local such as cloud metadata `169.254.169.254`, and other non-global ranges are refused); redirects are not followed | `test_private_or_plain_http_targets_are_refused` |
| Signed webhooks | Optional HMAC-SHA256 over timestamp and body, so receivers can authenticate ArgusAI and reject replays | `test_webhook_delivery_is_signed` |
| No notification storms | One message per channel, alert and severity band, plus a per-channel hourly cap (excess recorded as `suppressed`) | `test_escalation_notifies_once_per_new_severity_band`, `test_channel_rate_limit_suppresses_excess_deliveries` |
| Network placement | Only the notifier (and the optional mail catcher) sits on `egressnet`; the database, Redis, API workers and engine have no outbound route | `docker-compose.yml` |
| Retention | Old flows are purged automatically; alert evidence, alerts and the append-only audit log are kept | `test_retention_keeps_evidence_and_recent_flows` |

### Monitoring

- `/metrics` (Prometheus) is served by the API outside `/api/v1`, so the
  dashboard's allowlisted proxy never exposes it; in Compose the API port is
  bound to `127.0.0.1` and Prometheus reaches it on the internal network. It
  carries counts and timings only (no IPs, users or secrets), labels requests
  by route template so clients cannot inflate label cardinality, and can be
  turned off with `METRICS_ENABLED=false`.
- Grafana and Prometheus (optional `monitoring` profile) bind to `127.0.0.1`;
  Grafana sign-up is disabled and its admin password comes from
  `GRAFANA_ADMIN_PASSWORD`.

### Infrastructure

- Published ports bind to `127.0.0.1`; PostgreSQL and Redis are not published
  and sit on an internal Docker network with no internet route. The sensor
  overlay (`docker-compose.sensor.yml`) is the exception: it publishes Redis,
  on `127.0.0.1` unless `SENSOR_BIND` says otherwise, through a separate network
  that carries only Redis.
- Redis requires a password (`REDIS_PASSWORD`). Capture sensors use their own
  ACL account (`SENSOR_REDIS_PASSWORD`, disabled when unset) that may only
  `XADD` to `sentinel:flows` and `HSET`/`EXPIRE` keys under `sentinel:sensors:`;
  it cannot read anything, publish events, touch detections or settings, or run
  administrative commands.
- Application containers run as non-root users; images are minimal
  (`python:3.12-slim`, standalone Next.js on `node:24-alpine`).
- CI fails on high-severity advisories in production npm dependencies.
- Secrets come from the environment only; `.env` is git-ignored.

### Real-time engine

- The simulator generates traffic in-process and sends nothing on any network.
- Live capture is read-only sniffing and is the only mode that needs
  `CAP_NET_RAW`; the Compose `engine` service runs the simulator without
  extra capabilities, as a non-root user, on the internal network only.
- The engine has no database credentials: it reads its risk weights from
  Redis and writes detections to a capped Redis stream.
- The model bundle it loads is checksum-verified (see `ml/README.md`).
- Capture sensors send flow statistics only (addresses, ports, counts,
  timings), never payloads. Every flow entry from a sensor is validated
  (protocol version, sensor name, IP addresses, port and count ranges, finite
  timestamps near the engine's clock, exactly the 35 model features, size cap)
  and dropped if malformed, so a misbehaving sensor cannot crash or poison the
  engine's input format.

### Data pipeline

- At-least-once processing without duplicates (stream entry ids are unique),
  malformed input dead-lettered rather than blocking the queue, bounded
  dead-letter stream.
- Synthetic test detections are labelled (`source: sim`,
  `model_version: synthetic-demo`) and use documentation IP ranges
  (198.51.100.0/24, 203.0.113.0/24), so they cannot be mistaken for real
  traffic.

## Known gaps and residual risks

| Gap | Impact | Plan |
|---|---|---|
| No TLS termination | Credentials cross the network in clear text if the stack is exposed beyond localhost | Put a TLS reverse proxy in front for any shared deployment (see [Deploying beyond localhost](#deploying-beyond-localhost)) |
| No request-body size limit in the app server | Large bodies could consume memory | The same reverse proxy caps body size (example below) |
| Client-chosen IP when the dashboard is exposed directly | Next.js fills `X-Forwarded-For` from the socket only when the request has none, so a client talking to it directly can choose the IP the API sees: it could dodge the per-IP login limit (the per-username limit still applies) and falsify the IP in audit entries | The TLS reverse proxy recommended above must overwrite `X-Forwarded-For` with the peer address |
| Inline scripts allowed by the CSP | `'unsafe-inline'` weakens XSS protection; React escapes output and no HTML is rendered from data | Move to nonce-based CSP if the dashboard grows user-generated rich content |
| Throttling fails open | If Redis is down, logins are not rate-limited (argon2 still makes guessing slow) | Accepted for availability; logged as a warning |
| Strict refresh rotation | Concurrent refreshes are de-duplicated inside one Next.js process; running several dashboard replicas behind a load balancer would reintroduce false theft alarms | Run one dashboard replica, or move the refresh lock to Redis |
| Access tokens live up to 15 minutes after logout | A stolen access token stays usable until it expires unless the user changes password or is deactivated | Short TTL; version bump for hard revocation |
| Dev defaults | Default database passwords and an ephemeral JWT key are for local use | Set real values in `.env`; production mode refuses to start without `JWT_SECRET` |
| Unencrypted sensor link | Flow statistics and the sensor password cross the network in clear text when sensors run on other hosts | Keep `SENSOR_BIND` on `127.0.0.1` for a local sensor; for remote sensors use a VPN, SSH tunnel or a TLS proxy (e.g. stunnel) in front of Redis |
| Sensors can impersonate each other | Any holder of the sensor password can send flows under any sensor name or overwrite another sensor's status | One shared sensor account is the trade-off for simple setup; per-sensor ACL accounts would close it |
| Channel secrets stored in clear in PostgreSQL | Anyone with database access can read Slack webhook URLs and webhook signing secrets | Restrict database access; encrypting `notification_channels.config` with a key from the environment is a candidate improvement |
| DNS rebinding | The SSRF guard resolves the host before sending, and the HTTP client resolves it again; a hostile DNS server could answer differently the second time | Admin-only configuration limits who can set targets; pinning the connection to the checked address would close it |
| SMTP relay is trusted | `SMTP_*` settings come from the operator's environment and are not subject to the private-address check (relays usually are internal) | Use STARTTLS/TLS (`SMTP_SECURITY`) with a real relay |
| `/metrics` has no authentication | Anyone who can reach the API port directly can read operational counts (open alerts, flow rates) | Port bound to localhost; keep it off public interfaces or set `METRICS_ENABLED=false` |
| API rate limit fails open | If Redis is down, `/v2` keys are not rate-limited (batch size is still capped) | Accepted for availability, as with login throttling |
| `/v2/flows` trusts the customer's flows | A key holder can send fabricated flows and raise alerts under its own `api-<prefix>` sensor | Keys are per customer and revocable; the sensor name shows which key sent the flows |
| `/v2/detect` runs the model in the API process | Heavy use slows other API requests | Batch, rate and explanation caps; run more backend replicas or a separate detect service for real load |
| Model attacks (evasion, poisoning) | Adversarial traffic can be crafted to look benign | Documented limitation; model bundles are activated by admins only (Phase 4) |

## Deploying beyond localhost

The Compose defaults bind every port to `127.0.0.1`. To let other machines
reach the dashboard, put a TLS-terminating reverse proxy in front of the
**frontend only** (the API stays internal; the dashboard reaches it through
the backend-for-frontend). For example, with Caddy on the host:

```
soc.example.com {
	request_body {
		max_size 1MB
	}
	reverse_proxy 127.0.0.1:3000 {
		# Overwrite, never append: the API trusts this header from the dashboard.
		header_up X-Forwarded-For {remote_host}
	}
}
```

and in `.env`: `COOKIE_SECURE=true`, `DASHBOARD_URL=https://soc.example.com`,
`ENVIRONMENT=production`, a random `JWT_SECRET` (32+ characters), new database
passwords and a long `INITIAL_ADMIN_PASSWORD` (or change the generated one
after the first login). This closes the TLS, body-size and client-IP gaps
listed above.
