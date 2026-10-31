#!/usr/bin/env bash
# Prepare the hosted (serverless) database: migrations, admin + demo organization, a real scan of
# the DEMO fixture with the scanners installed on this machine, and the OWASP/CWE knowledge base.
# Idempotent. Prompts for the two secrets so they never land in shell history.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${DATABASE_URL:-}" ]; then
  read -rsp "Database connection string (postgresql://...): " DATABASE_URL; echo
fi
if [ -z "${DEMO_ADMIN_PASSWORD:-}" ]; then
  read -rsp "Admin password (same as DEMO_ADMIN_PASSWORD on Vercel): " DEMO_ADMIN_PASSWORD; echo
fi
export DATABASE_URL DEMO_ADMIN_PASSWORD
export ENVIRONMENT=production EMBEDDING_PROVIDER=none MODEL_PROVIDER=none
# Seeding signs no tokens and encrypts nothing, so the real secret keys are not needed here.
export SECRET_KEY="${SECRET_KEY:-prepare-only}" JWT_SECRET_KEY="${JWT_SECRET_KEY:-prepare-only}"

cd "$ROOT/backend"
exec .venv/bin/python -m app.db.seed.prepare_hosted
