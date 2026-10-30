"""Rebrand RiskLoom -> TRACE: rename the built-in MCP integration and the seeded demo org/admin.

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE mcp_integrations SET name = 'trace-security' WHERE name = 'riskloom-security'")
    op.execute("UPDATE organizations SET slug = 'trace-demo', name = 'TRACE Demo' "
               "WHERE slug = 'riskloom-demo' AND NOT EXISTS (SELECT 1 FROM organizations WHERE slug = 'trace-demo')")
    op.execute("UPDATE users SET email = 'admin@trace.example', full_name = 'TRACE Admin' "
               "WHERE email = 'admin@riskloom.dev' AND NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@trace.example')")


def downgrade() -> None:
    op.execute("UPDATE mcp_integrations SET name = 'riskloom-security' WHERE name = 'trace-security'")
    op.execute("UPDATE organizations SET slug = 'riskloom-demo', name = 'RiskLoom Demo' WHERE slug = 'trace-demo'")
    op.execute("UPDATE users SET email = 'admin@riskloom.dev', full_name = 'RiskLoom Admin' WHERE email = 'admin@trace.example'")
