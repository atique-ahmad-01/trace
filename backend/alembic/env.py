"""Alembic environment: uses the application's DATABASE_URL with a synchronous driver."""

from alembic import context
from sqlalchemy import create_engine, pool

from app.core.config import settings
from app.core.database import Base
from app.db import models  # noqa: F401  (register models)

target_metadata = Base.metadata


def sync_url() -> str:
    url = settings.DATABASE_URL
    return url.replace("sqlite+aiosqlite", "sqlite").replace("postgresql+asyncpg", "postgresql")


def run_migrations_offline() -> None:
    context.configure(url=sync_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(sync_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=conn.dialect.name == "sqlite")
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
