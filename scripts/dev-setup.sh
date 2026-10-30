#!/usr/bin/env bash
# One-time local setup without Docker: scanner binaries, Python 3.12 venv, backend deps, frontend deps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

bash scripts/install-tools.sh
export UV_PYTHON_INSTALL_DIR="$ROOT/.tools/python"
.tools/bin/uv python install 3.12
[ -d backend/.venv ] || .tools/bin/uv venv --python 3.12 backend/.venv
.tools/bin/uv pip install --python backend/.venv/bin/python -r backend/requirements.txt
(cd frontend && npm install)

if [ ! -f .env ]; then
  gen() { backend/.venv/bin/python -c "import secrets;print(secrets.token_urlsafe(48))"; }
  { echo "SECRET_KEY=$(gen)"; echo "JWT_SECRET_KEY=$(gen)"; } > .env
  echo "Created .env with fresh secrets (see .env.example for all options)"
fi
echo "Setup complete. Start with: scripts/dev.sh"
