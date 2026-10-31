# TRACE Architecture

> Trace every risk to a verified fix.

![TRACE architecture](architecture.svg)

- [1. System context](#1-system-context)
- [2. Scan pipeline](#2-scan-pipeline)
- [3. Agent investigation graph](#3-agent-investigation-graph)
- [4. Retrieval (security RAG)](#4-retrieval-security-rag)
- [5. Remediation lifecycle](#5-remediation-lifecycle)
- [6. MCP tool permissions](#6-mcp-tool-permissions)
- [7. Data model](#7-data-model)
- [8. Deployment topologies](#8-deployment-topologies)
- [9. Repository layout](#9-repository-layout)

---

## 1. System context

```mermaid
flowchart LR
    dev(["Developers & security teams"])
    gh[("GitHub<br/>App · webhooks · PRs")]
    feeds[("NVD · OSV · GHSA<br/>CISA KEV · OWASP · CWE")]
    llm[("Model providers<br/>Ollama · vLLM · Anthropic")]

    subgraph TRACE["TRACE"]
        ui["Next.js console"]
        api["FastAPI<br/>REST + OpenAPI"]
        jobs["Job runner<br/>RQ or in-process"]
        scan["Scan pipeline"]
        agents["LangGraph agents"]
        mcp["MCP layer"]
        db[("PostgreSQL / SQLite")]
        vec[("Qdrant")]
    end

    dev --> ui --> api
    api --> db
    api --> jobs
    gh -- "push / PR webhooks" --> api
    jobs --> scan
    jobs --> agents
    scan -- "authorized snapshot" --> gh
    agents --> mcp
    agents --> vec
    agents --> llm
    mcp --> feeds
    api -- "pull request after approval" --> gh
    scan --> db
    agents --> db
```

## 2. Scan pipeline

```mermaid
sequenceDiagram
    autonumber
    participant U as User / webhook
    participant API as FastAPI
    participant J as Job runner
    participant S as Snapshot
    participant SC as Scanners
    participant N as Normalizer
    participant DB as Database
    participant I as Intel engine

    U->>API: POST /scans (repo, branch, scanners)
    API->>DB: create Scan (PENDING), audit log
    API->>J: enqueue run_scan
    J->>S: shallow clone · hooks off · symlink and size guards
    S-->>J: snapshot path + commit SHA
    J->>J: detect ecosystems from manifests
    par Sandboxed subprocesses (no shell · minimal env · rlimits · timeout)
        J->>SC: Trivy (deps + misconfig)
        J->>SC: OSV-Scanner (deps)
        J->>SC: Semgrep (SAST)
        J->>SC: Gitleaks (secrets, redacted)
    end
    SC-->>N: JSON outputs
    N->>N: common schema → fingerprint → cross-scanner merge
    N->>DB: upsert findings · auto-resolve missing · flag regressions
    J->>S: delete snapshot (always)
    J->>I: enrich vuln ids (NVD · OSV · GHSA · KEV)
    I->>DB: cached records with per-source status
    opt auto_investigate
        J->>J: queue AI investigations for top CRITICAL/HIGH
    end
```

An unavailable scanner is recorded as `unavailable`, never replaced with synthetic results. A scan with some failed scanners is `PARTIAL`.

## 3. Agent investigation graph

```mermaid
flowchart TD
    start((START)) --> sup
    sup{{"Supervisor<br/>route · retry · fail-safe"}}
    sup -->|"next"| vr["Vulnerability research<br/>intel lookup · MCP osv_query_package · RAG"]
    sup -->|"next"| ca["Code analysis<br/>MCP read_file / search_code"]
    sup -->|"next"| ra["Risk assessment<br/>deterministic score + model rationale"]
    sup -->|"next"| rm["Remediation<br/>manifest patch · validated code patch"]
    vr --> sup
    ca --> sup
    ra --> sup
    rm --> sup
    sup -->|"all done"| fin["Finalize<br/>summary · citations · proposal"]
    fin --> done((END))

    classDef agent fill:#131c31,stroke:#f472b6,color:#e2e8f0
    classDef ctrl fill:#0f172a,stroke:#22d3ee,color:#e2e8f0
    class vr,ca,ra,rm agent
    class sup,fin ctrl
```

**What the agents may and may not decide:**

| Comes from structured data (never the model) | Comes from the model (labeled, citation-checked) |
|---|---|
| CVSS, fixed versions, KEV status, exploit refs | Summary, attack path, impact explanation |
| Risk score and priority (P1–P4) | Root cause, remediation rationale |
| Manifest upgrade patches | Code patch proposals (must parse; definitions preserved) |

Untrusted inputs (code, scanner text, retrieved documents) are wrapped as data and screened for injection markers. Source code is withheld from hosted models unless `ALLOW_SOURCE_TO_HOSTED_LLM=true`.

## 4. Retrieval (security RAG)

```mermaid
flowchart LR
    subgraph ingest["Ingestion"]
        o["OWASP Cheat Sheets<br/>+ Top 10"]
        c["MITRE CWE API"]
        v["Vulnerability records"]
        n["Approved internal docs<br/>(org-scoped)"]
    end
    o & c & v & n --> ch["Header-aware chunking"] --> em["Embeddings<br/>Ollama nomic-embed-text"] --> q[("Qdrant")]
    ch --> bm["BM25 index"]

    qry["Query + filters<br/>source · CWE · vuln id"] --> ex["Exact structured match<br/>(authoritative first)"]
    qry --> q
    qry --> bm
    q --> rrf["Reciprocal rank fusion"]
    bm --> rrf
    rrf --> rr["Rerank<br/>overlap + identifier boost"] --> cit["Evidence with citation ids S1…Sn"]
    ex --> cit
```

## 5. Remediation lifecycle

```mermaid
stateDiagram-v2
    [*] --> proposed: remediation agent
    proposed --> rejected: reviewer rejects
    proposed --> approved: reviewer approves (justify if evidence insufficient)
    approved --> verified: patch applies · target gone · no new HIGH/CRITICAL
    approved --> verification_failed: patch fails · syntax error · target remains · regression
    verification_failed --> approved: re-approve after review
    verified --> pr_opened: admin opens GitHub PR
    approved --> pr_opened: admin opens PR (unverified)
    pr_opened --> [*]: merged by humans, never automatically
    rejected --> [*]
```

Verification applies the patch with `git apply` to a fresh snapshot, syntax-checks changed files, and re-runs only the relevant scanners before and after. Repository code and tests are never executed; CI on the PR covers that.

## 6. MCP tool permissions

```mermaid
flowchart LR
    caller["Agent or admin"] --> a{"Integration active?"}
    a -- no --> deny["Denied + logged"]
    a -- yes --> b{"Tool on allowlist?"}
    b -- no --> deny
    b -- yes --> c{"Agent permitted<br/>for this tool?"}
    c -- no --> deny
    c -- yes --> d{"Requires approval?"}
    d -- "yes, not approved" --> deny
    d -- "no / approved" --> run["Execute with timeout<br/>(filesystem tools: snapshot root only)"] --> log["Execution log + audit"]
```

Servers come only from an allowlisted registry or remote HTTPS URLs added by an admin. New tools are denied by default.

## 7. Data model

```mermaid
erDiagram
    ORGANIZATION ||--o{ ORGANIZATION_MEMBER : has
    USER ||--o{ ORGANIZATION_MEMBER : joins
    ORGANIZATION ||--o{ REPOSITORY : owns
    ORGANIZATION ||--o{ CREDENTIAL : "stores (encrypted)"
    ORGANIZATION ||--o{ ORG_INTEGRATION : "connects (model, GitHub, Langfuse)"
    ORGANIZATION ||--o{ GITHUB_INSTALLATION : links
    REPOSITORY ||--o{ SCAN : runs
    REPOSITORY ||--o{ REPOSITORY_COMMIT : tracks
    SCAN ||--o{ SCANNER_EXECUTION : records
    REPOSITORY ||--o{ FINDING : has
    FINDING }o--o| VULNERABILITY_RECORD : "enriched by vuln_id"
    FINDING ||--o{ AGENT_INVESTIGATION : investigated
    AGENT_INVESTIGATION ||--o{ AGENT_EVENT : traces
    FINDING ||--o{ REMEDIATION_PROPOSAL : fixes
    REMEDIATION_PROPOSAL ||--o{ REMEDIATION_APPROVAL : reviewed
    REMEDIATION_PROPOSAL ||--o{ VERIFICATION_RUN : verified
    ORGANIZATION ||--o{ MCP_INTEGRATION : configures
    MCP_INTEGRATION ||--o{ MCP_TOOL : exposes
    MCP_TOOL ||--o{ MCP_TOOL_EXECUTION : logs
    RAG_SOURCE ||--o{ RAG_DOCUMENT : contains
    RAG_DOCUMENT ||--o{ RAG_CHUNK : splits
    ORGANIZATION ||--o{ AI_SECURITY_ASSESSMENT : runs
    AI_SECURITY_ASSESSMENT ||--o{ AI_SECURITY_RESULT : produces
    EVALUATION_DATASET ||--o{ EVALUATION_CASE : contains
    EVALUATION_DATASET ||--o{ EVALUATION_RUN : evaluated
    EVALUATION_RUN ||--o{ EVALUATION_RESULT : scores
    ORGANIZATION ||--o{ AUDIT_LOG : records
```

Every tenant-owned row carries `organization_id`; every query is scoped to the caller's organization and role.

## 8. Deployment topologies

```mermaid
flowchart TB
    subgraph local["Local (scripts/dev.sh)"]
        l1["uvicorn API<br/>+ in-process jobs"] --- l2[("SQLite")]
        l1 --- l3[("Embedded Qdrant")]
        l1 --- l4["Ollama (host)"]
        l5["next dev / next start"] --> l1
    end
    subgraph compose["Docker Compose"]
        c1["api"] --- c2[("PostgreSQL")]
        c1 --- c3[("Redis")]
        c4["RQ worker<br/>CPU/mem limits"] --- c3
        c4 --- c2
        c1 --- c5[("Qdrant")]
        c4 --- c5
        c4 --- c6["Ollama"]
        c7["frontend"] --> c1
    end
```

All containers run as non-root with `no-new-privileges` and every capability dropped.

## 9. Repository layout

```text
trace/
├── backend/                      FastAPI service (Python 3.12)
│   ├── app/
│   │   ├── main.py               app factory · middleware · health/ready · startup recovery
│   │   ├── api/
│   │   │   ├── common.py         serialization · pagination · org-scoped lookups
│   │   │   └── endpoints/        auth · organizations · repositories · scans · findings · intel
│   │   │                         agents · rag · mcp · ai_security · evaluations · remediation
│   │   │                         reports · dashboard · system · webhooks
│   │   ├── core/                 config · database · auth deps (RBAC) · security · logging · loop_lock
│   │   ├── db/
│   │   │   ├── models.py         32-table normalized schema
│   │   │   └── seed/             demo admin · org · fixture repository
│   │   ├── scanners/             runner (sandbox) · adapters (Trivy/OSV/Semgrep/Gitleaks)
│   │   │                         ecosystems · normalize (schema, fingerprints, dedupe)
│   │   ├── services/             scan_service · snapshot · patching · remediation_service
│   │   │                         ai_security · reports (PDF/JSON) · jobs · audit
│   │   ├── intel/                NVD · OSV · GHSA · CISA KEV aggregation and cache
│   │   ├── rag/                  ingestion · chunking · embeddings · hybrid retrieval
│   │   ├── agents/               LangGraph graph · prompts and injection defense · service
│   │   ├── llm/                  Ollama · OpenAI-compatible (vLLM) · Anthropic providers
│   │   ├── mcp/                  MCP client · registry · permissions · execution log
│   │   ├── mcp_servers/          trace_security: built-in MCP server (stdio)
│   │   ├── evals/                datasets · runner · security metrics
│   │   └── integrations/         registry: UI-managed per-org integrations (schema, encrypted
│   │                             storage, live verification, provider resolution, 409 gate)
│   │                             github: App · tokens · branches · pull requests
│   ├── alembic/versions/         0001 schema · 0002 rebrand data migration · 0003 org integrations
│   ├── tests/
│   │   ├── test_units.py         parsers · dedupe · patching · risk · guards · concurrency
│   │   ├── test_api.py           auth · org isolation · webhooks · approval gates · MCP allowlist
│   │   ├── test_integrations.py  integration storage · verification · gating · roles · env fallback
│   │   ├── test_e2e.py           scan → investigate → approve → verify (real scanners)
│   │   └── fixtures/vulnerable-app/   intentionally vulnerable demo target (never deploy)
│   ├── requirements.txt
│   └── Dockerfile                pinned scanners · non-root user
├── frontend/                     Next.js 14 App Router (TypeScript)
│   ├── app/                      overview · repositories · scans · vulnerabilities · investigations
│   │                             intelligence · ai-security · mcp · remediation · evaluations
│   │                             reports · settings · login
│   ├── components/               ui primitives · app shell · findings table · investigation view
│   │                             integrations panel · "set up first" prompt and banner
│   │   └── dashboard/            charts · posture gauge · lists
│   ├── lib/                      API client (auth, org header, downloads, integration_required
│   │                             interception) · integrations hooks · utils
│   └── Dockerfile                standalone build · non-root user
├── docs/
│   ├── ARCHITECTURE.md           this document
│   ├── STATUS.md                 verified vs. pending, known limitations
│   └── architecture.svg          overview diagram
├── scripts/
│   ├── install-tools.sh          uv · Trivy · Gitleaks · OSV-Scanner · Semgrep into .tools/
│   ├── dev-setup.sh              one-time local setup
│   └── dev.sh                    run API + frontend
├── docker-compose.yml            PostgreSQL · Redis · Qdrant · Ollama · API · worker · frontend
├── .env.example                  every configuration option, documented
├── LICENSE · SECURITY.md · CONTRIBUTING.md
├── .github/workflows/ci.yml      backend tests · frontend lint/type-check/build
└── README.md
```
