# Contributing to TRACE

Thanks for your interest! Issues and pull requests are welcome.

## Development setup

```bash
scripts/dev-setup.sh   # scanners, Python 3.12 venv, frontend deps, .env
scripts/dev.sh         # API on :8000, UI on :3000
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit together.

## Before opening a pull request

```bash
cd backend && .venv/bin/python -m pytest -q
cd frontend && npx tsc --noEmit && npx next lint && npx next build
```

- Add tests for behavior changes. Scanner parsers, patch generation and permission checks need unit tests.
- Never fabricate security data: no invented CVEs, scores, exploit status or benchmark numbers. Unavailable data must be reported as unavailable.
- Keep the guardrails intact: human approval before changes, no execution of repository code, untrusted input treated as data, and no source code sent to hosted models by default.
- Keep secrets out of commits. The only key material in the repository is the fake key in the test fixture.
