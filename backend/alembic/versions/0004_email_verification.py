"""users.email_verified; accounts that existed before verification was introduced count as verified.

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.true()))
    # New rows get False from the application; the server default only backfilled existing users.
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.alter_column("email_verified", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("email_verified")
