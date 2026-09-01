#!/usr/bin/env sh
set -eu

action="${1:-up}"
cd "$(dirname "$0")/.."

case "$action" in
  up) docker compose up --build -d --wait ;;
  down) docker compose down ;;
  reset) docker compose down --volumes --remove-orphans ;;
  status) docker compose ps ;;
  logs) docker compose logs --follow --tail 200 ;;
  *) echo "usage: $0 {up|down|reset|status|logs}" >&2; exit 2 ;;
esac
