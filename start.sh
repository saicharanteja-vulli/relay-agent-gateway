#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python -c "import fastapi, uvicorn, certifi" 2>/dev/null; then
  .venv/bin/python -m pip install -r requirements.txt
fi
.venv/bin/python -m relay.worker &
worker_pid=$!
trap 'kill "$worker_pid" 2>/dev/null || true' EXIT INT TERM
.venv/bin/python -m uvicorn relay.app:app --host 127.0.0.1 --port "${PORT:-8080}" --no-proxy-headers
