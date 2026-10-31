"""UI-managed integrations: org_integrations table; existing GitHub token credentials become the github integration.

Revision ID: 0003
Revises: 0002
"""
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_integrations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=50), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secrets", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("status_message", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "kind", name="uq_org_integration"),
    )
    with op.batch_alter_table("org_integrations", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_org_integrations_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_org_integrations_organization_id"), ["organization_id"], unique=False)

    # Carry stored GitHub tokens over (already Fernet-encrypted; copied as-is, never decrypted here).
    conn = op.get_bind()
    table = sa.table(
        "org_integrations",
        sa.column("id", sa.Uuid()), sa.column("organization_id", sa.Uuid()), sa.column("kind", sa.String()),
        sa.column("config", sa.JSON()), sa.column("secrets", sa.JSON()), sa.column("status", sa.String()),
        sa.column("status_message", sa.Text()), sa.column("details", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)), sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    rows = conn.execute(sa.text("SELECT organization_id, encrypted_value, last4 FROM credentials WHERE kind = 'github_token' ORDER BY updated_at")).fetchall()
    latest = {r[0]: r for r in rows}
    now = datetime.now(timezone.utc)
    for org_id, enc, last4 in latest.values():
        op.bulk_insert(table, [{
            "id": uuid.uuid4(), "organization_id": org_id if isinstance(org_id, uuid.UUID) else uuid.UUID(str(org_id)), "kind": "github", "config": {}, "secrets": {"token": {"value": enc, "last4": last4}},
            "status": "unverified", "status_message": "Imported from stored credentials — verify to confirm access",
            "details": {}, "created_at": now, "updated_at": now,
        }])


def downgrade() -> None:
    with op.batch_alter_table("org_integrations", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_org_integrations_organization_id"))
        batch_op.drop_index(batch_op.f("ix_org_integrations_created_at"))
    op.drop_table("org_integrations")
