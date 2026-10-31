"""
Application Configuration

All configuration is environment-driven. Defaults are suitable for local
development (SQLite, in-process jobs, embedded Qdrant, local Ollama).
"""

from pathlib import Path
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from typing_extensions import Annotated

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_DIR / ".env"), str(BACKEND_DIR / ".env")),
        case_sensitive=True,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "TRACE"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Security
    SECRET_KEY: str = "dev-insecure-secret-change-me"
    JWT_SECRET_KEY: str = "dev-insecure-jwt-secret-change-me"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 720
    # Fernet key (urlsafe base64, 32 bytes) for encrypting stored credentials.
    # If unset, a key is derived from SECRET_KEY.
    ENCRYPTION_KEY: Optional[str] = None

    # CORS
    CORS_ORIGINS: Annotated[List[str], NoDecode] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    ALLOWED_HOSTS: Annotated[List[str], NoDecode] = ["*"]

    # Database (sqlite+aiosqlite for local, postgresql+asyncpg in compose)
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BACKEND_DIR / 'trace.db'}"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis / jobs. If REDIS_URL is unset or unreachable, jobs run in-process.
    REDIS_URL: Optional[str] = None
    RQ_QUEUE_NAME: str = "trace"
    JOB_TIMEOUT_SECONDS: int = 1800

    # GitHub
    GITHUB_APP_ID: Optional[str] = None
    GITHUB_APP_PRIVATE_KEY_PATH: Optional[str] = None
    GITHUB_APP_SLUG: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None  # optional PAT for public API rate limits / advisories
    GITHUB_API_URL: str = "https://api.github.com"

    # Integrations (model provider, GitHub token, Langfuse) are configured per organization in
    # Settings -> Integrations. The env values below act as a fallback for orgs that have not
    # configured one. Unset => fallback on everywhere except ENVIRONMENT=production.
    INTEGRATIONS_ENV_FALLBACK: Optional[bool] = None

    # Model providers
    MODEL_PROVIDER: str = "ollama"  # ollama | openai_compatible | anthropic | none
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"
    OPENAI_COMPATIBLE_BASE_URL: Optional[str] = None  # e.g. vLLM http://host:8000/v1
    OPENAI_COMPATIBLE_API_KEY: Optional[str] = None
    OPENAI_COMPATIBLE_MODEL: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-5-5"
    # Hosted providers never receive source code unless this is true.
    ALLOW_SOURCE_TO_HOSTED_LLM: bool = False
    LLM_TIMEOUT_SECONDS: int = 300
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 1200
    # USD per 1M tokens, used for cost estimates in evaluations ("model=in/out,...")
    LLM_PRICING: str = "claude-sonnet-5-5=3/15"

    # Embeddings / RAG
    EMBEDDING_PROVIDER: str = "ollama"  # ollama | none
    EMBEDDING_MODEL: str = "nomic-embed-text"
    QDRANT_URL: Optional[str] = None  # unset -> embedded local storage
    QDRANT_PATH: str = str(BACKEND_DIR / "storage" / "qdrant")
    QDRANT_API_KEY: Optional[str] = None
    QDRANT_COLLECTION: str = "trace_security_knowledge"
    RAG_CHUNK_SIZE: int = 900
    RAG_CHUNK_OVERLAP: int = 120
    RAG_TOP_K: int = 6

    # Scanners
    TOOLS_DIR: str = str(PROJECT_DIR / ".tools" / "bin")
    GIT_PATH: str = "git"
    TRIVY_PATH: str = "trivy"
    SEMGREP_PATH: str = "semgrep"
    GITLEAKS_PATH: str = "gitleaks"
    OSV_SCANNER_PATH: str = "osv-scanner"
    SCANNER_TIMEOUT: int = 600
    SCANNER_MEMORY_LIMIT_MB: int = 4096
    SCANNER_OFFLINE: bool = False  # disables scanner network access where supported
    SEMGREP_CONFIG: str = "auto"  # registry rules; set to a local path for offline
    WORK_DIR: str = str(BACKEND_DIR / "storage" / "work")
    MAX_REPO_SIZE_MB: int = 500

    # Vulnerability intelligence
    NVD_API_KEY: Optional[str] = None
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_API_URL: str = "https://api.osv.dev/v1"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    INTEL_CACHE_TTL_HOURS: int = 24
    INTEL_HTTP_TIMEOUT: int = 20

    # MCP
    MCP_TOOL_TIMEOUT: int = 120

    # Remediation
    REMEDIATION_PR_BRANCH_PREFIX: str = "trace/fix-"

    # Observability
    LANGFUSE_PUBLIC_KEY: Optional[str] = None
    LANGFUSE_SECRET_KEY: Optional[str] = None
    LANGFUSE_HOST: str = "https://cloud.langfuse.com"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 300

    # Demo / seed
    SEED_DEMO_DATA: bool = True
    DEMO_ADMIN_EMAIL: str = "admin@trace.example"
    DEMO_ADMIN_PASSWORD: str = "trace-admin"

    @field_validator("CORS_ORIGINS", "ALLOWED_HOSTS", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @property
    def env_integrations_enabled(self) -> bool:
        if self.INTEGRATIONS_ENV_FALLBACK is not None:
            return self.INTEGRATIONS_ENV_FALLBACK
        return self.ENVIRONMENT != "production"

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def async_database_url(self) -> str:
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


settings = Settings()
