#!/usr/bin/env bash
# End-to-end check of a running stack. Start it first:
#   docker compose up -d --build --wait
#   ./scripts/smoke_test.sh
set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:${BACKEND_PORT:-8000}}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:${FRONTEND_PORT:-3000}}"

fail() { echo "FAIL: $*" >&2; exit 1; }

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

echo "OK: frontend -> backend -> PostgreSQL + Redis"
