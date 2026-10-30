#!/usr/bin/env bash
# Run backend (http://localhost:8000) and frontend (http://localhost:3000) for local development.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

(cd "$ROOT/backend" && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000) &
BACK=$!
(cd "$ROOT/frontend" && npx next dev -p 3000) &
FRONT=$!
trap 'kill $BACK $FRONT 2>/dev/null' EXIT INT TERM
wait
