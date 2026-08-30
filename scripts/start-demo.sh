#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"
FRONTEND_DIR="$PROJECT_DIR/prototype"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required."
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is required. Install it with: npm install -g pnpm"
  exit 1
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
  python3 -m venv "$PROJECT_DIR/.venv"
fi

if ! "$VENV_PYTHON" -c "import intentguard, fastapi, uvicorn" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -e "$PROJECT_DIR[api,dev]"
fi

if [[ ! -x "$FRONTEND_DIR/node_modules/.bin/vinext" ]]; then
  (
    cd "$FRONTEND_DIR"
    pnpm install --frozen-lockfile
  )
fi

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
issue_local_token() {
  local subject="$1"
  local role="$2"
  local response
  response="$(curl --fail --silent \
    -X POST http://127.0.0.1:9000/token \
    -H 'Content-Type: application/json' \
    -d "{\"sub\":\"$subject\",\"roles\":[\"$role\"],\"agent_id\":\"agt_travel_01\",\"customer_id\":\"demo-customer\"}")"
  printf '%s' "$response" | \
    "$VENV_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
export NEXT_PUBLIC_INTENTGUARD_ACCESS_TOKEN="$(
  issue_local_token local-demo-admin admin
)"
export NEXT_PUBLIC_INTENTGUARD_AGENT_ACCESS_TOKEN="$(
  issue_local_token local-demo-agent agent
)"
export NEXT_PUBLIC_INTENTGUARD_OPERATOR_ACCESS_TOKEN="$(
  issue_local_token local-demo-operator operator
)"
export NEXT_PUBLIC_INTENTGUARD_REVIEWER_ACCESS_TOKEN="$(
  issue_local_token local-demo-reviewer reviewer
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
pnpm run dev
