#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"
FRONTEND_DIR="$PROJECT_DIR/prototype"

if [[ ! -x "$VENV_PYTHON" ]]; then
  python3 -m venv "$PROJECT_DIR/.venv"
fi

if ! "$VENV_PYTHON" -c "import fastapi, httpx" >/dev/null 2>&1; then
  "$VENV_PYTHON" -m pip install -e "$PROJECT_DIR[api,dev]"
fi

PYTHONPATH="$PROJECT_DIR/src" "$VENV_PYTHON" \
  -m unittest discover -s "$PROJECT_DIR/tests" -v

cd "$FRONTEND_DIR"
./node_modules/.bin/vinext build
node --test tests/rendered-html.test.mjs
./node_modules/.bin/eslint app lib tests
