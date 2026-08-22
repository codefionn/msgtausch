#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

choose_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    echo "podman compose"
    return
  fi
  if command -v podman-compose >/dev/null 2>&1; then
    echo "podman-compose"
    return
  fi
  echo "No Compose command found" >&2
  exit 127
}

COMPOSE_CMD=$(choose_compose)
read -r -a COMPOSE <<<"$COMPOSE_CMD"

cleanup() {
  "${COMPOSE[@]}" down -v --remove-orphans
}
trap cleanup EXIT

cleanup
"${COMPOSE[@]}" build
"${COMPOSE[@]}" up --abort-on-container-exit --exit-code-from client
