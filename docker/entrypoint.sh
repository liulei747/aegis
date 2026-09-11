#!/usr/bin/env bash
# Entrypoint: `serve` (default) runs the API; anything else is exec'd verbatim so
#   docker compose run --rm aegis assemble --workspace /workspace --rule-config p/default
# works as expected.
set -euo pipefail

if [ "${1:-serve}" = "serve" ]; then
    shift || true
    exec uvicorn app.main:app \
        --host "${AEGIS_HOST:-0.0.0.0}" \
        --port "${AEGIS_PORT:-8000}" \
        --workers "${AEGIS_WORKERS:-1}" \
        --no-access-log \
        --log-config /opt/aegis/docker-logging.json \
        "$@"
fi

exec aegis "$@"
