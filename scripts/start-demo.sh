#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"
FRONTEND_DIR="$PROJECT_DIR/prototype"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required."
  exit 1
fi

# package.json pins pnpm@11.24.0, which is what CI installs with. Prefer
# corepack so a different pnpm on PATH cannot produce a lockfile CI then
# refuses -- exactly what happened when a local pnpm 10 relocked a tree CI
# reads with pnpm 11.
if command -v corepack >/dev/null 2>&1; then
  PNPM=(corepack pnpm@11.24.0)
elif command -v pnpm >/dev/null 2>&1; then
  PNPM=(pnpm)
else
  echo "pnpm is required. Install Node 22+ (which ships corepack), or: npm install -g pnpm"
  exit 1
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
  python3 -m venv "$PROJECT_DIR/.venv"
fi

if ! "$VENV_PYTHON" -c "import intentguard, fastapi, uvicorn" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -e "$PROJECT_DIR[api,dev]"
fi

# Probing for one binary is not proof the lockfile is satisfied: a partial or
# stale node_modules that happens to contain vinext skipped the install and
# then died on a missing cross-env. pnpm install is fast and a no-op when
# everything already matches, so just run it.
(
  cd "$FRONTEND_DIR"
  CI=true "${PNPM[@]}" install --frozen-lockfile
)

# The one-command demo uses an ephemeral issuer bound only to loopback. Run the
# API directly with real JWT/JWKS settings in non-demo environments.
"$VENV_PYTHON" -u "$PROJECT_DIR/examples/local_jwks_server.py" &
JWKS_PID=$!
API_PID=""
CONNECTOR_PID=""
cleanup() {
  if [[ -n "$API_PID" ]]; then
    kill "$API_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$CONNECTOR_PID" ]]; then
    kill "$CONNECTOR_PID" >/dev/null 2>&1 || true
  fi
  kill "$JWKS_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
for _ in {1..50}; do
  if curl --fail --silent \
    http://127.0.0.1:9000/.well-known/jwks.json >/dev/null; then
    break
  fi
  sleep 0.2
done
if ! curl --fail --silent \
  http://127.0.0.1:9000/.well-known/jwks.json >/dev/null; then
  kill "$JWKS_PID" >/dev/null 2>&1 || true
  echo "The local JWKS server did not start within 10 seconds."
  exit 1
fi
# A token names the one agent it may act for -- the gateway rejects any
# mismatch (api.py require_match). The console drives three demo agents, so it
# needs three agent tokens, not one.
issue_local_token() {
  local subject="$1"
  local role="$2"
  local agent="${3:-agt_refund_01}"
  local response
  response="$(curl --fail --silent \
    -X POST http://127.0.0.1:9000/token \
    -H 'Content-Type: application/json' \
    -d "{\"sub\":\"$subject\",\"roles\":[\"$role\"],\"agent_id\":\"$agent\",\"customer_id\":\"demo-customer\"}")"
  printf '%s' "$response" | \
    "$VENV_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
export NEXT_PUBLIC_INTENTGUARD_ACCESS_TOKEN="$(
  issue_local_token local-demo-admin admin
)"
export NEXT_PUBLIC_INTENTGUARD_AGENT_ACCESS_TOKEN="$(
  issue_local_token local-demo-agent agent agt_refund_01
)"
# One token per demo agent, keyed by agent id, so a scenario can authorize as
# whichever agent it belongs to.
export NEXT_PUBLIC_INTENTGUARD_AGENT_TOKENS="$(
  "$VENV_PYTHON" -c 'import json,sys; print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))' \
    agt_refund_01 "$(issue_local_token local-demo-agent-ada agent agt_refund_01)" \
    agt_refund_02 "$(issue_local_token local-demo-agent-bo agent agt_refund_02)" \
    agt_billing_03 "$(issue_local_token local-demo-agent-cy agent agt_billing_03)"
)"
export NEXT_PUBLIC_INTENTGUARD_OPERATOR_ACCESS_TOKEN="$(
  issue_local_token local-demo-operator operator
)"
export NEXT_PUBLIC_INTENTGUARD_REVIEWER_ACCESS_TOKEN="$(
  issue_local_token local-demo-reviewer reviewer
)"
# The chat panel talks to /v1/agent/message, which is guarded by
# customer_principal and takes customer_id from the verified token.
export NEXT_PUBLIC_INTENTGUARD_CUSTOMER_ACCESS_TOKEN="$(
  issue_local_token demo-customer customer agt_refund_01
)"
export INTENTGUARD_CONNECTOR_ACCESS_TOKEN="$(
  issue_local_token local-booking-connector connector
)"
export INTENTGUARD_JWT_ISSUER=http://127.0.0.1:9000
export INTENTGUARD_JWKS_URL=http://127.0.0.1:9000/.well-known/jwks.json
export INTENTGUARD_JWT_AUDIENCE=intentguard-api

API_ARGS=(
  -m uvicorn intentguard.api:app
  --app-dir "$PROJECT_DIR/src"
  --host 127.0.0.1
  --port 8000
  --reload
  --reload-dir "$PROJECT_DIR/src"
)
# Local secrets live in .env, which is gitignored. Anything already exported
# wins, so the shell still beats the file.
if [[ -f "$PROJECT_DIR/.env" ]]; then
  API_ARGS+=(--env-file "$PROJECT_DIR/.env")
  echo "Loading environment from .env"
fi

"$VENV_PYTHON" "${API_ARGS[@]}" &
API_PID=$!

for _ in {1..50}; do
  if curl --fail --silent http://127.0.0.1:8000/health >/dev/null; then
    break
  fi
  sleep 0.2
done
if ! curl --fail --silent http://127.0.0.1:8000/health >/dev/null; then
  echo "The IntentGuard API did not start within 10 seconds."
  exit 1
fi
"$VENV_PYTHON" -m intentguard.booking_connector &
CONNECTOR_PID=$!

echo "IntentGuard API: http://127.0.0.1:8000"
echo "Protected booking connector: http://127.0.0.1:8100"
echo "IntentGuard console will use port 3000 or the next available local port."

cd "$FRONTEND_DIR"
"${PNPM[@]}" run dev
