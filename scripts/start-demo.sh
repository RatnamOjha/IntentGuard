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

if ! "$VENV_PYTHON" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -e "$PROJECT_DIR[api,dev]"
fi

if [[ ! -x "$FRONTEND_DIR/node_modules/.bin/vinext" ]]; then
  (
    cd "$FRONTEND_DIR"
    pnpm install --frozen-lockfile
  )
fi

"$VENV_PYTHON" -m uvicorn intentguard.api:app \
  --app-dir "$PROJECT_DIR/src" \
  --host 127.0.0.1 \
  --port 8000 \
  --reload \
  --reload-dir "$PROJECT_DIR/src" &
API_PID=$!

cleanup() {
  kill "$API_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "IntentGuard API: http://127.0.0.1:8000"
echo "IntentGuard console will use port 3000 or the next available local port."

cd "$FRONTEND_DIR"
pnpm run dev
