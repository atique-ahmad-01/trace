# Security Policy

TRACE is alpha software. Please report vulnerabilities in TRACE itself privately.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** for this repository (Security tab → "Report a vulnerability"). Please do not open public issues for security problems.

Include affected version or commit, steps to reproduce, and impact. We aim to acknowledge reports within 7 days.

## Scope

In scope: the TRACE backend, frontend, MCP server, scan sandboxing, authentication/authorization, and secret handling.

Out of scope:
- `backend/tests/fixtures/vulnerable-app/` is **intentionally vulnerable** demo code. Its vulnerable dependencies, insecure code and fake key material are deliberate. Never deploy it.
- Vulnerabilities in third-party scanners or models (report those upstream).

## Deployment notes

- Set strong `SECRET_KEY` and `JWT_SECRET_KEY`; production startup refuses the development defaults.
- Change `DEMO_ADMIN_PASSWORD` or set `SEED_DEMO_DATA=false` outside local development.
- Run scanners in the provided containers (non-root, no capabilities, resource limits) for isolation; local mode only applies process limits.
- Keep `ALLOW_SOURCE_TO_HOSTED_LLM=false` unless you have authorization to send repository code to a hosted model provider.
