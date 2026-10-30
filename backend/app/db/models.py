"""
Database Models

Normalized schema for TRACE. Uses portable types (Uuid, JSON) so the same
models run on PostgreSQL and SQLite. Every tenant-owned row carries an
organization_id (directly or via its parent) for org-level isolation.
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class UUIDMixin:
    id = Column(Uuid, primary_key=True, default=uuid.uuid4)


def org_fk(nullable: bool = False):
    return Column(Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=nullable, index=True)


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


SEVERITY_ORDER = {s.value: i for i, s in enumerate(Severity)}


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"  # some scanners failed or were unavailable
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


# --------------------------------------------------------------------------- identity


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(255))
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    github_username = Column(String(100))
    avatar_url = Column(String(500))

    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")


class Organization(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organizations"

    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text)
    settings = Column(JSON, default=dict)

    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    repositories = relationship("Repository", back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "organization_members"

    organization_id = org_fk()
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), default="member", nullable=False)  # owner | admin | member | viewer

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_member"),)


class Credential(Base, UUIDMixin, TimestampMixin):
    """Encrypted organization credentials (e.g. GitHub token). Values never leave the backend."""

    __tablename__ = "credentials"

    organization_id = org_fk()
    kind = Column(String(50), nullable=False)  # github_token | llm_api_key | ...
    name = Column(String(100), nullable=False)
    encrypted_value = Column(Text, nullable=False)
    last4 = Column(String(8))

    __table_args__ = (UniqueConstraint("organization_id", "kind", "name", name="uq_credential"),)


class GitHubInstallation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "github_installations"

    organization_id = org_fk()
    installation_id = Column(String(50), unique=True, nullable=False)
    account_login = Column(String(255))
    account_type = Column(String(50))
    permissions = Column(JSON, default=dict)
    repository_selection = Column(String(50))
    suspended = Column(Boolean, default=False)


# --------------------------------------------------------------------------- repositories & scans


class Repository(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "repositories"

    organization_id = org_fk()
    installation_id = Column(Uuid, ForeignKey("github_installations.id", ondelete="SET NULL"))
    provider = Column(String(30), default="github", nullable=False)  # github | git | local
    github_id = Column(String(100), index=True)
    name = Column(String(255), nullable=False)
    full_name = Column(String(500), nullable=False)
    description = Column(Text)
    clone_url = Column(String(1000))
    html_url = Column(String(1000))
    default_branch = Column(String(200), default="main")
    language = Column(String(80))
    ecosystems = Column(JSON, default=list)
    is_private = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    is_demo = Column(Boolean, default=False, nullable=False)
    last_scanned_at = Column(DateTime(timezone=True))
    last_scanned_commit = Column(String(64))
    security_score = Column(Float)
    extra = Column(JSON, default=dict)

    organization = relationship("Organization", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")
    commits = relationship("RepositoryCommit", back_populates="repository", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("organization_id", "full_name", name="uq_repo_org_name"),)


class RepositoryCommit(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "repository_commits"

    repository_id = Column(Uuid, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    sha = Column(String(64), nullable=False)
    branch = Column(String(200))
    message = Column(Text)
    author = Column(String(255))
    committed_at = Column(DateTime(timezone=True))

    repository = relationship("Repository", back_populates="commits")

    __table_args__ = (UniqueConstraint("repository_id", "sha", name="uq_repo_commit"),)


class Scan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scans"

    organization_id = org_fk()
    repository_id = Column(Uuid, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    commit_sha = Column(String(64))
    branch = Column(String(200))
    trigger = Column(String(50), default="manual")  # manual | webhook_push | webhook_pr | verification
    triggered_by = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    status = Column(String(20), default=ScanStatus.PENDING.value, nullable=False, index=True)
    is_demo = Column(Boolean, default=False, nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    scanners_requested = Column(JSON, default=list)
    ecosystems = Column(JSON, default=list)
    total_findings = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    log = Column(JSON, default=list)
    auto_investigate = Column(Boolean, default=False)

    repository = relationship("Repository", back_populates="scans")
    scanner_executions = relationship("ScannerExecution", back_populates="scan", cascade="all, delete-orphan")


class ScannerExecution(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scanner_executions"

    scan_id = Column(Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner_name = Column(String(50), nullable=False)
    scanner_version = Column(String(100))
    status = Column(String(30), nullable=False)  # completed | failed | unavailable | skipped | timeout
    command = Column(JSON)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Float)
    findings_count = Column(Integer, default=0)
    exit_code = Column(Integer)
    stderr_tail = Column(Text)
    error_message = Column(Text)

    scan = relationship("Scan", back_populates="scanner_executions")


class Finding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "findings"

    organization_id = org_fk()
    repository_id = Column(Uuid, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    first_scan_id = Column(Uuid, ForeignKey("scans.id", ondelete="SET NULL"))
    last_scan_id = Column(Uuid, ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    fingerprint = Column(String(64), nullable=False)
    scanner_name = Column(String(50), nullable=False, index=True)
    detected_by = Column(JSON, default=list)  # all scanners that reported the same issue
    finding_type = Column(String(30), nullable=False, index=True)  # dependency | sast | secret | misconfig | ai_security
    rule_id = Column(String(300))
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(10), default=Severity.UNKNOWN.value, nullable=False, index=True)
    status = Column(String(20), default=FindingStatus.OPEN.value, nullable=False, index=True)
    is_demo = Column(Boolean, default=False, nullable=False)

    vuln_id = Column(String(100), index=True)  # primary identifier (CVE preferred, else GHSA/OSV id)
    aliases = Column(JSON, default=list)
    cwe_ids = Column(JSON, default=list)
    cvss_score = Column(Float)

    file_path = Column(String(1000))
    start_line = Column(Integer)
    end_line = Column(Integer)
    code_snippet = Column(Text)

    package_name = Column(String(300), index=True)
    package_ecosystem = Column(String(50))
    installed_version = Column(String(100))
    fixed_version = Column(String(200))

    commit_sha = Column(String(64))
    first_seen_at = Column(DateTime(timezone=True), default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow)
    resolved_at = Column(DateTime(timezone=True))
    references = Column(JSON, default=list)
    raw_data = Column(JSON)

    risk_score = Column(Float)  # set by risk agent
    priority = Column(String(10))  # P1..P4

    repository = relationship("Repository", back_populates="findings")
    investigations = relationship("AgentInvestigation", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint", name="uq_finding_fingerprint"),
        Index("ix_finding_pkg", "package_name", "installed_version"),
    )


# --------------------------------------------------------------------------- intelligence


class VulnerabilityRecord(Base, UUIDMixin, TimestampMixin):
    """Cached, source-attributed vulnerability intelligence keyed by identifier."""

    __tablename__ = "vulnerability_records"

    vuln_id = Column(String(100), unique=True, nullable=False, index=True)
    aliases = Column(JSON, default=list)
    summary = Column(Text)
    description = Column(Text)
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    cvss_severity = Column(String(20))
    cwe_ids = Column(JSON, default=list)
    published_at = Column(DateTime(timezone=True))
    modified_at = Column(DateTime(timezone=True))
    affected = Column(JSON, default=list)  # [{ecosystem, package, ranges, fixed}]
    fixed_versions = Column(JSON, default=list)
    references = Column(JSON, default=list)
    is_known_exploited = Column(Boolean)  # None => KEV data unavailable
    kev = Column(JSON)
    exploit_references = Column(JSON, default=list)
    sources = Column(JSON, default=dict)  # {nvd: {status, fetched_at}, osv: {...}, kev: {...}, ghsa: {...}}
    remediation = Column(Text)
    fetched_at = Column(DateTime(timezone=True), default=utcnow)


class KEVEntry(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "kev_entries"

    cve_id = Column(String(30), unique=True, nullable=False, index=True)
    vendor = Column(String(255))
    product = Column(String(255))
    name = Column(String(500))
    date_added = Column(String(20))
    due_date = Column(String(20))
    required_action = Column(Text)
    known_ransomware = Column(String(30))
    notes = Column(Text)


class IntelSyncState(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "intel_sync_state"

    source = Column(String(50), unique=True, nullable=False)
    last_synced_at = Column(DateTime(timezone=True))
    status = Column(String(30))
    detail = Column(Text)
    record_count = Column(Integer, default=0)


# --------------------------------------------------------------------------- agents


class AgentInvestigation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "agent_investigations"

    organization_id = org_fk()
    finding_id = Column(Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    status = Column(String(30), default="pending", nullable=False, index=True)
    mode = Column(String(30), default="agentic_rag")  # agentic_rag | rag | base
    model = Column(String(200))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)

    summary = Column(Text)
    research = Column(JSON)
    code_analysis = Column(JSON)
    risk_assessment = Column(JSON)
    remediation = Column(JSON)
    evidence = Column(JSON, default=list)
    citations = Column(JSON, default=list)
    tokens_in = Column(Integer, default=0)
    tokens_out = Column(Integer, default=0)
    latency_ms = Column(Integer)

    finding = relationship("Finding", back_populates="investigations")
    events = relationship(
        "AgentEvent", back_populates="investigation", cascade="all, delete-orphan", order_by="AgentEvent.sequence"
    )


class AgentEvent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "agent_events"

    investigation_id = Column(Uuid, ForeignKey("agent_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    agent_name = Column(String(80), nullable=False)
    event_type = Column(String(40), nullable=False)  # start | tool_call | evidence | decision | error | complete
    message = Column(Text)
    data = Column(JSON)
    duration_ms = Column(Integer)

    investigation = relationship("AgentInvestigation", back_populates="events")


# --------------------------------------------------------------------------- RAG


class RagSource(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rag_sources"

    organization_id = org_fk(nullable=True)  # NULL => global knowledge
    name = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)  # owasp | cwe | osv | nvd | kev | ghsa | internal | framework
    url = Column(String(1000))
    trust_level = Column(String(30), default="authoritative")  # authoritative | approved_internal
    last_ingested_at = Column(DateTime(timezone=True))
    document_count = Column(Integer, default=0)
    status = Column(String(30), default="pending")
    detail = Column(Text)


class RagDocument(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rag_documents"

    source_id = Column(Uuid, ForeignKey("rag_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    external_id = Column(String(300), nullable=False)
    title = Column(String(500))
    url = Column(String(1000))
    content = Column(Text, nullable=False)
    doc_metadata = Column(JSON, default=dict)
    content_hash = Column(String(64))
    chunk_count = Column(Integer, default=0)
    embedded = Column(Boolean, default=False)

    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_rag_doc"),)


class RagChunk(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rag_chunks"

    document_id = Column(Uuid, ForeignKey("rag_documents.id", ondelete="CASCADE"), nullable=False, index=True)
    chunk_index = Column(Integer, nullable=False)
    text = Column(Text, nullable=False)
    chunk_metadata = Column(JSON, default=dict)


# --------------------------------------------------------------------------- MCP


class MCPIntegration(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mcp_integrations"

    organization_id = org_fk()
    name = Column(String(100), nullable=False)
    description = Column(Text)
    transport = Column(String(20), default="stdio")  # stdio | streamable_http
    command = Column(JSON)  # argv for stdio servers (from an allowlisted registry)
    url = Column(String(1000))
    is_builtin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    status = Column(String(30), default="unknown")  # connected | error | unknown
    status_detail = Column(Text)
    last_connected_at = Column(DateTime(timezone=True))

    tools = relationship("MCPTool", back_populates="integration", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_mcp_name"),)


class MCPTool(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mcp_tools"

    integration_id = Column(Uuid, ForeignKey("mcp_integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    input_schema = Column(JSON)
    is_allowed = Column(Boolean, default=False)  # explicit allowlist; default deny
    requires_approval = Column(Boolean, default=False)
    sensitivity = Column(String(20), default="read")  # read | write | network
    allowed_agents = Column(JSON, default=list)

    integration = relationship("MCPIntegration", back_populates="tools")

    __table_args__ = (UniqueConstraint("integration_id", "name", name="uq_mcp_tool"),)


class MCPToolExecution(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "mcp_tool_executions"

    organization_id = org_fk()
    tool_id = Column(Uuid, ForeignKey("mcp_tools.id", ondelete="CASCADE"), nullable=False, index=True)
    invoked_by = Column(String(100))  # user:<id> | agent:<name>
    investigation_id = Column(Uuid, ForeignKey("agent_investigations.id", ondelete="SET NULL"))
    arguments = Column(JSON)
    status = Column(String(20))  # success | error | denied | timeout
    result_preview = Column(Text)
    error_message = Column(Text)
    duration_ms = Column(Integer)


# --------------------------------------------------------------------------- remediation


class RemediationProposal(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_proposals"

    organization_id = org_fk()
    finding_id = Column(Uuid, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(Uuid, ForeignKey("agent_investigations.id", ondelete="SET NULL"))
    proposed_by = Column(String(100))
    title = Column(String(500))
    root_cause = Column(Text)
    description = Column(Text)
    remediation_type = Column(String(50))  # dependency_upgrade | code_patch | secret_rotation | config_change | guidance
    patch = Column(Text)  # unified diff
    files_changed = Column(JSON, default=list)
    side_effects = Column(Text)
    evidence_sufficient = Column(Boolean, default=False)
    confidence = Column(String(20))
    status = Column(String(30), default="proposed", nullable=False, index=True)
    # proposed | approved | rejected | applied | pr_opened | verified | verification_failed
    base_commit = Column(String(64))
    pr_number = Column(Integer)
    pr_url = Column(String(1000))
    branch_name = Column(String(300))

    finding = relationship("Finding")
    approvals = relationship("RemediationApproval", back_populates="proposal", cascade="all, delete-orphan")
    verifications = relationship("VerificationRun", back_populates="proposal", cascade="all, delete-orphan")


class RemediationApproval(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "remediation_approvals"

    proposal_id = Column(Uuid, ForeignKey("remediation_proposals.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    decision = Column(String(20), nullable=False)  # approved | rejected
    comment = Column(Text)

    proposal = relationship("RemediationProposal", back_populates="approvals")


class VerificationRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "verification_runs"

    proposal_id = Column(Uuid, ForeignKey("remediation_proposals.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(30), default="pending")  # pending | running | passed | failed | error
    patch_applied = Column(Boolean)
    scanners = Column(JSON, default=list)
    target_finding_present_before = Column(Boolean)
    target_finding_present_after = Column(Boolean)
    findings_before = Column(Integer)
    findings_after = Column(Integer)
    new_findings = Column(JSON, default=list)  # regressions
    resolved_findings = Column(JSON, default=list)
    details = Column(JSON)
    error_message = Column(Text)
    completed_at = Column(DateTime(timezone=True))

    proposal = relationship("RemediationProposal", back_populates="verifications")


# --------------------------------------------------------------------------- AI security


class AISecurityAssessment(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ai_security_assessments"

    organization_id = org_fk()
    name = Column(String(255), nullable=False)
    description = Column(Text)
    target_type = Column(String(50), nullable=False)  # repository | llm_endpoint
    repository_id = Column(Uuid, ForeignKey("repositories.id", ondelete="SET NULL"))
    target_config = Column(JSON, default=dict)  # endpoint provider/model/system prompt; never secrets
    test_suites = Column(JSON, default=list)
    status = Column(String(30), default="pending", nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    total_tests = Column(Integer, default=0)
    tests_passed = Column(Integer, default=0)
    tests_failed = Column(Integer, default=0)
    tests_errored = Column(Integer, default=0)
    risk_score = Column(Float)
    summary = Column(Text)

    results = relationship("AISecurityResult", back_populates="assessment", cascade="all, delete-orphan")


class AISecurityResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ai_security_results"

    assessment_id = Column(Uuid, ForeignKey("ai_security_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    test_id = Column(String(100), nullable=False)
    category = Column(String(80), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    outcome = Column(String(20), nullable=False)  # failed (risk found) | passed | error | not_applicable
    severity = Column(String(10))
    evidence = Column(JSON)
    reproduction = Column(Text)
    impact = Column(Text)
    mitigation = Column(Text)
    verification_status = Column(String(30), default="unverified")
    file_path = Column(String(1000))
    line_number = Column(Integer)

    assessment = relationship("AISecurityAssessment", back_populates="results")


# --------------------------------------------------------------------------- evaluation


class EvaluationDataset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evaluation_datasets"

    organization_id = org_fk(nullable=True)  # NULL => built-in
    name = Column(String(255), nullable=False)
    description = Column(Text)
    task_type = Column(String(50), nullable=False)  # vuln_analysis | prompt_injection | cve_matching
    is_builtin = Column(Boolean, default=False)

    cases = relationship("EvaluationCase", back_populates="dataset", cascade="all, delete-orphan")


class EvaluationCase(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evaluation_cases"

    dataset_id = Column(Uuid, ForeignKey("evaluation_datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    case_key = Column(String(100), nullable=False)
    input = Column(JSON, nullable=False)
    expected = Column(JSON, nullable=False)
    tags = Column(JSON, default=list)

    dataset = relationship("EvaluationDataset", back_populates="cases")


class EvaluationRun(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evaluation_runs"

    organization_id = org_fk()
    dataset_id = Column(Uuid, ForeignKey("evaluation_datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255))
    mode = Column(String(30), nullable=False)  # base | rag | agentic_rag
    provider = Column(String(50))
    model = Column(String(200))
    status = Column(String(30), default="pending", nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    metrics = Column(JSON)
    case_limit = Column(Integer)

    results = relationship("EvaluationResult", back_populates="run", cascade="all, delete-orphan")


class EvaluationResult(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "evaluation_results"

    run_id = Column(Uuid, ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(Uuid, ForeignKey("evaluation_cases.id", ondelete="CASCADE"), nullable=False)
    output = Column(JSON)
    scores = Column(JSON)
    passed = Column(Boolean)
    latency_ms = Column(Integer)
    tokens_in = Column(Integer, default=0)
    tokens_out = Column(Integer, default=0)
    error_message = Column(Text)

    run = relationship("EvaluationRun", back_populates="results")


# --------------------------------------------------------------------------- audit


class AuditLog(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    organization_id = org_fk(nullable=True)
    user_id = Column(Uuid, ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor = Column(String(100))  # user email, "system", "webhook", "agent:<name>"
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100))
    resource_id = Column(String(64))
    details = Column(JSON)
    ip_address = Column(String(64))
