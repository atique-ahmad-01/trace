"""
API Router

Main API router that includes all endpoint modules.
"""

from fastapi import APIRouter

from app.api.endpoints import (
    agents,
    ai_security,
    auth,
    dashboard,
    evaluations,
    findings,
    integrations,
    mcp,
    organizations,
    rag,
    remediation,
    reports,
    repositories,
    scans,
    system,
    vulnerability_intelligence,
    webhooks,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["Integrations"])
api_router.include_router(repositories.router, prefix="/repositories", tags=["Repositories & GitHub"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(vulnerability_intelligence.router, prefix="/intel", tags=["Vulnerability Intelligence"])
api_router.include_router(agents.router, prefix="/agents", tags=["Agent Investigations"])
api_router.include_router(rag.router, prefix="/rag", tags=["RAG Knowledge"])
api_router.include_router(mcp.router, prefix="/mcp", tags=["MCP Integrations"])
api_router.include_router(ai_security.router, prefix="/ai-security", tags=["AI Security"])
api_router.include_router(evaluations.router, prefix="/evaluations", tags=["Evaluations"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(system.router, prefix="/system", tags=["System"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
