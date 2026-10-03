#!/usr/bin/env bash
# End-to-end check of a running stack. Start it first:
#   docker compose up -d --build --wait
#   ./scripts/smoke_test.sh
#
# With ADMIN_PASSWORD set (the INITIAL_ADMIN_PASSWORD used at first start), it
# also logs in, pushes synthetic detections through the alert engine and checks
# the audit log is append-only for the application's database role.
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

echo "-> frontend           $FRONTEND_URL/"
page="$(curl -fsS "$FRONTEND_URL/")" || fail "frontend unreachable"
grep -q "All systems operational" <<<"$page" \
  || fail "frontend does not report all services online"

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

echo "-> synthetic detections -> alert engine -> alert"
target="203.0.113.$((RANDOM % 200 + 20))"
docker compose exec -T alert-engine \
  python -m app.cli demo-detections --count 10 --target "$target" >/dev/null
for _ in $(seq 1 30); do
  found="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/alerts?ip=$target" \
    | json_field '["total"]')"
  [[ "$found" -ge 1 ]] && break
  sleep 1
done
[[ "${found:-0}" -ge 1 ]] || fail "no alert raised for $target"
alert="$(curl -fsS "${auth[@]}" "$BACKEND_URL/api/v1/alerts?ip=$target" | json_field '["items"][0]')"
echo "   $alert"

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

echo "OK: stack healthy, auth + RBAC, detection pipeline and audit trail verified"
