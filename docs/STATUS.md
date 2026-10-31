# TRACE: Project Status

**Alpha.** Status as of 2026-10-30. This page records what has been verified end to end, what depends on credentials or infrastructure that was not available during development, and known limitations.

## 1. What was implemented

**Backend** (FastAPI, SQLAlchemy 2 async, Alembic):
- **Data model.** 32-table normalized schema with UUID keys and org-scoped rows, covering users, organizations, members, credentials, org integrations, GitHub installations, repositories, commits, scans, scanner executions, findings, vulnerability records, KEV, RAG sources/documents/chunks, MCP integrations/tools/executions, investigations, agent events, remediation proposals, approvals, verification runs, AI-security assessments/results, evaluation datasets/cases/runs/results, and the audit log. It runs on SQLite or PostgreSQL. Migrations are in `alembic/versions/` (0001 schema, 0002 rebrand, 0003 org integrations).
- **Auth and access control.** JWT, bcrypt, roles (viewer/member/admin/owner), org isolation via `X-Organization-Id`, Fernet-encrypted credentials and integration secrets, rate limiting, security headers, secret-redacting logs, and an audit trail.
- **Scanning.**
  - Snapshots: hook-less shallow clone with the token passed via env, or an allowed local fixture. Escaping symlinks are pruned, size is capped, and cleanup is guaranteed.
  - Ecosystems are detected from manifests and lock files.
  - The four scanners run in parallel as sandboxed subprocesses (no shell, minimal env, timeout with process-group kill, rlimits).
  - Output is parsed from each scanner's JSON, normalized, fingerprinted and deduplicated across scanners. Findings are upserted, marked auto-resolved when no longer detected, and flagged as regressions when they reappear.
  - A posture score is computed per repository.
- **Vulnerability intelligence.** NVD 2.0 (rate limited), OSV.dev, GHSA and the CISA KEV catalog. Records are cached with a TTL and carry per-source status (`ok`, `not_found`, `unavailable`, `skipped`). KEV membership is NULL (unknown) when KEV data is unavailable.
- **RAG.**
  - Ingests OWASP Cheat Sheets and Top 10, MITRE CWE, vulnerability records and org-internal docs.
  - Pipeline: header-aware chunking → Ollama embeddings (`nomic-embed-text`) → Qdrant (server or embedded).
  - Retrieval: BM25 and dense search fused with RRF, metadata filters (source/CWE/vuln id), a heuristic rerank, exact structured matches first, and citation ids.
- **Agents.**
  - LangGraph `StateGraph` with typed state and explicit transitions: supervisor (routing, retries, failure handling) → vulnerability_research → code_analysis → risk_assessment → remediation → finalize.
  - Agents use real tools: intel lookups, RAG, and MCP `osv_query_package`, `search_code` and `read_file` against an authorized snapshot.
  - The risk score is deterministic. Model claims whose citations aren't in the evidence are flagged as unsupported. Injection markers are detected, source code is withheld from hosted models, and events are persisted live.
- **MCP.**
  - The built-in stdio server (`app/mcp_servers/trace_security.py`) exposes OSV, NVD, KEV and CWE lookups, filesystem tools restricted to the snapshot root, and Gitleaks.
  - The client discovers tools and keeps an allowlisted server registry. Arbitrary commands are rejected, and remote servers must use https.
  - Tools are default-deny, with per-agent permissions, approval for sensitive tools, timeouts, and logging of every call including denials.
- **Remediation.**
  - Deterministic manifest upgrade patches (requirements.txt, package.json — including lock-file findings — pyproject and go.mod). Model-proposed code patches are validated into unified diffs.
  - Explicit approval is required, with a justification if evidence is insufficient. Guidance-only proposals cannot be approved for application.
  - Verification applies the patch with `git apply` to a fresh snapshot and re-runs the relevant scanners before and after. It passes only if the target finding disappears with no new HIGH/CRITICAL findings.
  - GitHub PR creation via the Git Data API, never merged.
- **AI security.** 11 static checks for AI/agent code (heuristic, with file and line evidence) and 8 live adversarial probes judged deterministically with a random canary. Custom probes are supported.
- **Evaluations.** Three built-in datasets (code analysis with safe snippets, prompt-injection resistance, CVE matching with ground truth checked against OSV). Runs compare base, RAG and agentic RAG. Metrics: accuracy, CWE, severity, FP/FN rate, remediation correctness, CVE recall/precision/hallucination rate against live OSV, groundedness, citation coverage, injection resistance, tool-use correctness, completion, latency, tokens and cost.
- **Reports.** Executive, repository, vulnerability, AI-security, remediation and evaluation reports as JSON or PDF (ReportLab).
- **Webhooks.** GitHub push, pull_request and installation events, with signature verification and installation permission checks.
- **Recovery.** Health and readiness endpoints, a service status endpoint, and startup recovery of jobs interrupted by a restart.

**Frontend** (Next.js 14 App Router, TypeScript, Tailwind with shadcn-style primitives, Lucide, React Query, Recharts):
- A dark-first app shell with live service indicators and 20 routes.
- Pages: overview dashboard, repositories (onboarding, connect, detail, scan launcher), scans and scan detail with live logs, vulnerabilities (filters) and finding detail (intel, AI investigation, timeline, evidence, remediation), investigations, intelligence (lookup, tracked records, KEV, RAG playground and ingestion), AI security, MCP (permissions, execution, logs), remediation (diff review, approval, verification, PR), evaluations (runs, comparison chart, case results), reports (PDF/JSON), and settings (integrations, status, members, audit). A global "set up first" prompt and banner appear when a feature needs an integration that is missing or failed verification.
- Every page reads from the API. Demo data is labeled and can be filtered out.

## 2. What has been verified

Verification environment: Intel macOS, Python 3.12 (uv), Node 22, local Ollama, SQLite, in-process jobs, embedded Qdrant.

- **Scanning:** Trivy 0.76.1, OSV-Scanner 2.7.0, Semgrep 1.182.1 and Gitleaks 8.30.1 all executed on the vulnerable fixture. 88 raw findings deduplicated to 61 unique (5 critical / 26 high / 28 medium / 2 low). Trivy and OSV results merged on the same CVE; Gitleaks and Semgrep merged on the same secret. (That run used an earlier Stripe-style fake key. The published fixture uses a random PEM block that only Gitleaks detects, so GitHub push protection does not block the repository; counts differ slightly.)
- **Live intelligence:** 41 identifiers enriched. NVD 40 ok, OSV 40 ok, GHSA 41 ok. KEV catalog synced (1,764 entries).
- **Live RAG:** 72 documents (28 OWASP, 44 CWE) → 1,149 chunks, all embedded in Qdrant.
- **Live LangGraph investigation** (Ollama `qwen2.5-coder:7b`) on CVE-2020-14343 / PyYAML:
  - The real MCP `osv_query_package` call confirmed the exact affected version.
  - 7 cited evidence items. Deterministic risk 8.3 (P2).
  - Correct patch generated: `pyyaml==5.3 → 5.4`.
  - That run predates the timeout fix: 3 of 4 model calls timed out on this CPU. It now reports `partial` in that situation; the timeout was raised and one retry added.
- **Second live investigation** (after the timeout fix) on the SAST `eval()` injection in `src/app.py`:
  - Status `completed`: all four agents produced model output. The run used 4,806 input and 761 output tokens and took about 12.6 minutes on this CPU while other jobs were also running.
  - The code agent read the file through MCP `read_file` and reported "User input → eval() → code execution", reachable. Risk 7.0 (P2).
  - **It exposed a safety bug.** The model's "high confidence" code patch deleted the whole route and inserted invalid Python, and was still marked evidence-sufficient. Two guards are now in place:
    - Model patches must parse (Python via `ast`, bracket balance for JS/Java/Go and others) and must not remove function, class or decorator definitions.
    - Verification syntax-checks the changed files after `git apply`.
  - A regression test reproduces the exact broken patch.
- **Live evaluation** — CVE-matching dataset, 2 cases (PyYAML 5.3, Jinja2 2.10), Ollama `qwen2.5-coder:7b`:

  | Mode | CVE recall | CVE precision | Hallucinated-ID rate | Groundedness | Citation coverage | Tool-use correctness | p50 latency |
  |---|---|---|---|---|---|---|---|
  | Base (no RAG) | 0% | 0% | 100% | n/a | n/a | n/a | 181 s |
  | RAG | 50% | 50% | 50% | 100% | 100% | n/a | 141 s |
  | Agentic RAG (OSV tool + retrieval) | **100%** | **100%** | **0%** | 100% | 100% | 100% | 164 s |

  With only 2 cases this sample is far too small for statistical claims. It does show the evaluation pipeline working end to end, and the expected effect: without tools, the model invents CVE IDs.
- **Concurrency bugs found by these runs, now fixed:**
  - Module-level `asyncio.Lock` objects were bound to one job thread's event loop; they are now per-loop.
  - The shared BM25 index could be read while another thread was rebuilding it; rebuilds now publish an atomic snapshot.
  - Both fixes have regression tests.
- **Live AI-security assessments:**
  - Repository review of the fixture: 8 of 11 checks flagged risk, with file and line evidence in `src/agent.py`.
  - Endpoint probes against `qwen3:1.7b`: 4 of 8 demonstrated risk (canary leaked twice, forbidden `delete_all_customers` tool call, cross-user lookup).
- **Automated tests:** `pytest`: 29 passed (18 unit, 10 API, 1 end-to-end). The end-to-end test runs real scanners, the graph, a proposal, approval, and verification with real `git apply` and re-scan. Verification passed: the target was present before and absent after.
- **Frontend:** `tsc`, `next lint` and `next build` are clean. All routes return 200 from the production server, and the CORS preflight passes.

## 3. How to run

```bash
scripts/dev-setup.sh   # once
scripts/dev.sh         # backend :8000, frontend :3000, API docs :8000/docs
```

Sign in as `admin@trace.example` with `DEMO_ADMIN_PASSWORD` (default `trace-admin`, local only). For Docker, see the README (`docker compose up -d --build`).

## 4. Required environment variables

Nothing is strictly required locally; `scripts/dev-setup.sh` generates `SECRET_KEY` and `JWT_SECRET_KEY`. Production startup refuses the dev secrets. Everything else is in `.env.example`, with GitHub App, Redis, Qdrant and NVD key as the main optional groups. The model provider, GitHub token and Langfuse are configured per organization in **Settings → Integrations**. Their environment variables are only a fallback, which is on by default in development and off when `ENVIRONMENT=production` (`INTEGRATIONS_ENV_FALLBACK` overrides).

## 5. Tests

```bash
cd backend && .venv/bin/python -m pytest -q
cd frontend && npx tsc --noEmit && npx next lint && npx next build
```

## 6. Integrations verified vs credential-dependent

| Integration | Status |
|---|---|
| Trivy, OSV-Scanner, Semgrep, Gitleaks | **Verified** (real runs) |
| NVD, OSV.dev, GHSA (unauthenticated), CISA KEV | **Verified** live |
| OWASP and MITRE CWE ingestion, Ollama embeddings, embedded Qdrant | **Verified** live |
| Ollama chat models (agents, probes, evals) | **Verified** live (slow on this CPU), including setup and verification through Settings → Integrations |
| MCP built-in server (stdio) | **Verified** — discovery and tool calls from agents |
| GitHub public repos via anonymous API / https clone | Implemented. Not yet exercised; tests use the local fixture. |
| GitHub App (installation tokens, webhooks), private repos, PR creation | **Requires credentials** (App id + key, or a token with contents and pull-request write). The code paths are implemented; webhook signature handling is tested; nothing was run against GitHub. |
| vLLM / OpenAI-compatible, Anthropic | **Requires endpoint or key**. Adapters implemented. An Anthropic key is checked live during verification (an invalid key was confirmed to be rejected); chat with a valid key was not exercised. |
| PostgreSQL | **Verified**: all migrations (0001–0003, including the GitHub-token import) and the full test suite, end-to-end test included, pass on PostgreSQL 16.2 (`TEST_DATABASE_URL=… pytest`). |
| Redis/RQ, Qdrant server, Docker Compose | Implemented, **not yet verified**: Docker was unavailable in the development environment. Job modules are tested to import standalone, as RQ workers load them. |
| Production deployment (Vercel frontend, Render API + PostgreSQL) | Configured (`render.yaml`, Vercel project). See the README's Production section. |
| Langfuse | Optional; requires keys. Configured per org in Settings → Integrations; verification is tested with mocked HTTP only. |
| GitHub MCP server template | Requires Docker and a token. Not exercised. |

## 7. Known limitations

- **Speed:** local 7B inference on this Intel CPU takes about 1–3 minutes per model call, so a full investigation takes about 10 minutes. Use a GPU host, vLLM, or a hosted provider for interactive speed.
- **Embedded Qdrant** is single-process. Use `QDRANT_URL` with RQ workers, as Compose does.
- **Isolation:** without Docker, scanners are isolated with rlimits and a minimal environment only. Memory limits are not enforced on macOS, and network access is not restricted (scanners need their vulnerability databases). Container-level isolation applies only under Compose.
- **Verification** does not run repository tests: TRACE never executes repository code, so CI on the PR is expected to cover that. Verification of lock-file-only upgrades (npm) fails honestly until the lock file is regenerated.
- **AI-security static checks** are regex heuristics marked "needs review". Passing tests do not prove an AI system is secure.
- **RAGAS** is not bundled. Groundedness and citation metrics are custom deterministic equivalents.
- The reranker is heuristic (lexical overlap plus identifier match), not a cross-encoder.
- Semgrep is pinned to 1.182.1, the last release with Intel macOS builds; newer versions are fine on Linux and Apple Silicon.
- Single-language UI. There is no GitHub OAuth login; email/password only.
