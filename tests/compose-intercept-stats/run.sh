#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

choose_compose() {
  # Prefer Docker Compose for CI parity and better depends_on semantics
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi
  # Fallbacks: Podman Compose variants
  if command -v podman >/dev/null 2>&1; then
    if podman compose version >/dev/null 2>&1; then
      echo "podman compose"
      return 0
    fi
  fi
  if command -v podman-compose >/dev/null 2>&1; then
    echo "podman-compose"
    return 0
  fi
  echo "No compose tool found (docker compose/docker-compose, podman compose, or podman-compose)" >&2
  exit 127
}

COMPOSE_CMD=$(choose_compose)
echo "Using compose: ${COMPOSE_CMD}"

${COMPOSE_CMD} down

# Build and run tests
${COMPOSE_CMD} pull || true
${COMPOSE_CMD} build
${COMPOSE_CMD} up --build --abort-on-container-exit --exit-code-from client
EXIT_CODE=$?

# Cleanup
${COMPOSE_CMD} down -v --remove-orphans

exit $EXIT_CODE