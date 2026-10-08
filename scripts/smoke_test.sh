#!/usr/bin/env bash
# End-to-end check of a running stack. Start it first:
#   docker compose up -d --build --wait
#   ./scripts/smoke_test.sh
#
# With ADMIN_PASSWORD set (the INITIAL_ADMIN_PASSWORD used at first start), it
# also logs in, pushes synthetic detections through the alert engine and checks
# the audit log is append-only for the application's database role.
# With MAILPIT_URL set (stack started with the "mail" profile and SMTP_HOST=mailpit)
# it also checks that the DDoS alert is emailed through the notifier.
# Needs curl and python3; the authenticated part also needs docker compose.
set -euo pipefail

cd "$(dirname "$0")/.."

BACKEND_URL="${BACKEND_URL:-http://localhost:${BACKEND_PORT:-8000}}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:${FRONTEND_PORT:-3000}}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"

fail() { echo "FAIL: $*" >&2; exit 1; }
json_field() { python3 -c "import json, sys; print(json.load(sys.stdin)$1)"; }

# Responses are captured before matching: piping curl into `grep -q` can make
# curl fail with a write error once grep exits early, which pipefail reports.

echo "-> backend liveness   $BACKEND_URL/health"
live="$(curl -fsS "$BACKEND_URL/health")" || fail "backend unreachable"
grep -q '"status":"ok"' <<<"$live" || fail "backend /health returned: $live"

echo "-> backend readiness  $BACKEND_URL/health/ready"
ready="$(curl -sS "$BACKEND_URL/health/ready")" || fail "backend unreachable"
echo "   $ready"
grep -q '"status":"ready"' <<<"$ready" || fail "a backend dependency is down"

echo "-> backend metrics    $BACKEND_URL/metrics"
metrics="$(curl -fsS "$BACKEND_URL/metrics")" || fail "metrics endpoint unreachable"
grep -q '^sentinel_open_alerts{severity="CRITICAL"}' <<<"$metrics" || fail "pipeline gauges missing from /metrics"

echo "-> frontend status    $FRONTEND_URL/status"
page="$(curl -fsS "$FRONTEND_URL/status")" || fail "frontend unreachable"
grep -q "All systems operational" <<<"$page" \
  || fail "frontend does not report all services online"

echo "-> dashboard requires a session"
location="$(curl -sS -o /dev/null -w '%{redirect_url}' "$FRONTEND_URL/alerts")"
[[ "$location" == *"/login?next=%2Falerts" ]] || fail "/alerts did not redirect to login: '$location'"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$FRONTEND_URL/api/backend/alerts")"
[[ "$code" == 401 ]] || fail "API proxy without a session returned $code, expected 401"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$FRONTEND_URL/api/backend/alerts/1/ack")"
[[ "$code" == 403 ]] || fail "API proxy accepted a request without the CSRF header ($code)"

if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "OK: frontend -> backend -> PostgreSQL + Redis"
  echo "(set ADMIN_PASSWORD to also test login, the alert pipeline and the audit log)"
  exit 0
fi

echo "-> login as $ADMIN_USERNAME"
tokens="$(curl -fsS -X POST "$BACKEND_URL/api/v1/auth/login" \
  --data-urlencode "username=$ADMIN_USERNAME" --data-urlencode "password=$ADMIN_PASSWORD")" \
  || fail "login failed"
token="$(json_field '["access_token"]' <<<"$tokens")"
auth=(-H "Authorization: Bearer $token")
role="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/auth/me" | json_field '["role"]')"
[[ "$role" == "admin" ]] || fail "expected role admin, got $role"
unauthenticated="$(curl -s -o /dev/null -w '%{http_code}' "$BACKEND_URL/api/v1/alerts")"
[[ "$unauthenticated" == "401" ]] || fail "alerts readable without a token ($unauthenticated)"

echo "-> engine is classifying traffic"
for _ in $(seq 1 30); do
  events="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/stats/summary?window=1h" \
    | json_field '["events"]')"
  [[ "$events" -ge 1 ]] && break
  sleep 2
done
[[ "${events:-0}" -ge 1 ]] || fail "no flows reached the database"
echo "   $events flows analysed"

if [[ -n "${MAILPIT_URL:-}" ]]; then
  echo "-> email notification channel (delivered to $MAILPIT_URL)"
  channel="$(curl -fsS "${auth[@]}" -H "Content-Type: application/json" \
    -X POST "$BACKEND_URL/api/v1/notifications/channels" \
    -d "{\"name\":\"smoke-test mail $(date +%s)\",\"kind\":\"email\",\"min_severity\":\"HIGH\",\"config\":{\"recipients\":[\"soc@example.com\"]}}")" \
    || fail "could not create a notification channel"
  channel_id="$(json_field '["id"]' <<<"$channel")"
fi

echo "-> simulated DDoS -> ML engine -> risk -> alert engine -> alert"
target="10.20.0.10"  # the simulator's web server
open_query="$BACKEND_URL/api/v1/alerts?ip=$target&attack_type=ddos&status=NEW&status=INVESTIGATING&status=CONTAINED"
already_open="$(curl -fsS "${auth[@]}" "$open_query" | json_field '["total"]')"
docker compose exec -T engine \
  python -m sentinel_engine inject --scenario ddos --duration 10 >/dev/null
query="$BACKEND_URL/api/v1/alerts?ip=$target&attack_type=ddos"
for _ in $(seq 1 30); do
  found="$(curl -fsS "${auth[@]}" "$query" | json_field '["total"]')"
  [[ "$found" -ge 1 ]] && break
  sleep 1
done
[[ "${found:-0}" -ge 1 ]] || fail "no DDoS alert raised for $target"
alert_id="$(curl -fsS "${auth[@]}" "$query" | json_field '["items"][0]["id"]')"
detail="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/alerts/$alert_id")"
echo "   $(json_field '["description"]' <<<"$detail") (risk $(json_field '["risk_score"]' <<<"$detail"), $(json_field '["severity"]' <<<"$detail"))"
grep -q '"model_version":"sentinel-flow-' <<<"$detail" || fail "alert not produced by the trained model"

if [[ -n "${MAILPIT_URL:-}" && "$already_open" -gt 0 ]]; then
  # The detections joined an alert that was already open at its severity, so
  # by design no channel is notified again (fresh stacks, as in CI, test this).
  echo "-> alert notification: skipped, a DDoS alert on $target was already open"
elif [[ -n "${MAILPIT_URL:-}" ]]; then
  echo "-> alert notification: outbox -> notifier -> SMTP"
  for _ in $(seq 1 30); do
    status="$(curl -fsS "${auth[@]}" \
      "$BACKEND_URL/api/v1/notifications/deliveries?channel_id=$channel_id&alert_id=$alert_id" \
      | python3 -c "import json, sys; i = json.load(sys.stdin)['items']; print(i[0]['status'] if i else 'none')")"
    [[ "$status" == "sent" || "$status" == "failed" ]] && break
    sleep 1
  done
  [[ "$status" == "sent" ]] || fail "notification delivery status: $status"
  subject="$(curl -fsS "$MAILPIT_URL/api/v1/messages" \
    | python3 -c "import json, sys; print(next((m['Subject'] for m in json.load(sys.stdin)['messages'] if 'DDoS' in m['Subject']), ''))")"
  grep -q "DDoS detected" <<<"$subject" || fail "no alert email in the mail catcher (got '$subject')"
  echo "   $subject"
fi

echo "-> audit log is append-only for the application role"
app_user="${APP_DB_USER:-sentinel_app}"
db_name="${POSTGRES_DB:-sentinel}"
# Must fail because of the append-only trigger, not for any other reason.
tamper="$(docker compose exec -T db psql -U "$app_user" -d "$db_name" -v ON_ERROR_STOP=1 \
  -c "DELETE FROM audit_logs" 2>&1)" && fail "the application role could delete audit entries"
grep -q "append-only" <<<"$tamper" || fail "unexpected error from the tamper check: $tamper"
entries="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/audit?action=auth.login" \
  | json_field '["total"]')"
[[ "$entries" -ge 1 ]] || fail "login was not audited"

echo "OK: stack healthy, auth + RBAC, ML detection pipeline and audit trail verified"
