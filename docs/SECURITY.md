# Security controls

What SentinelAI implements today (Phase 3), how it is verified, and what is
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
  `Cache-Control: no-store` and a restrictive CSP on `/api/*`.
- Readiness probe reports only `ok`/`error`; failure details stay in logs.
- No CORS headers are sent: browsers cannot call the API cross-origin. The
  Phase 6 dashboard will reach it through a same-origin backend-for-frontend.

### Infrastructure

- Published ports bind to `127.0.0.1`; PostgreSQL and Redis are not published
  and sit on an internal Docker network with no internet route.
- Application containers run as non-root users; images are minimal
  (`python:3.12-slim`, standalone Next.js on `node:24-alpine`).
- CI fails on high-severity advisories in production npm dependencies.
- Secrets come from the environment only; `.env` is git-ignored.

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
| No TLS termination | Credentials cross the network in clear text if the stack is exposed beyond localhost | Put a reverse proxy (Caddy/nginx) with TLS in front for any shared deployment; documented in Phase 8 |
| No request-body size limit in the app server | Large bodies could consume memory | The same reverse proxy should cap body size |
| Per-IP throttling behind a proxy | Behind the Phase 6 BFF every request shares one IP, so the per-IP limit would apply to all users together | Trust `X-Forwarded-For` from the BFF only (uvicorn `--forwarded-allow-ips`) in Phase 6 |
| Throttling fails open | If Redis is down, logins are not rate-limited (argon2 still makes guessing slow) | Accepted for availability; logged as a warning |
| Strict refresh rotation | Two tabs refreshing the same token at once end the session (treated as theft) | Accepted; the BFF will refresh centrally |
| Access tokens live up to 15 minutes after logout | A stolen access token stays usable until it expires unless the user changes password or is deactivated | Short TTL; version bump for hard revocation |
| Dev defaults | Default database passwords and an ephemeral JWT key are for local use | Set real values in `.env`; production mode refuses to start without `JWT_SECRET` |
| Model attacks (evasion, poisoning) | Adversarial traffic can be crafted to look benign | Documented limitation; model bundles are activated by admins only (Phase 4) |
