"""
Database Configuration

Async SQLAlchemy engine that works with PostgreSQL (asyncpg) and SQLite (aiosqlite).
"""

from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


def _make_engine(url: str):
    if url.startswith("sqlite"):
        eng = create_async_engine(url, connect_args={"timeout": 30})

        @event.listens_for(eng.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return eng
    return create_async_engine(
        url,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
    )


engine = _make_engine(settings.async_database_url)

async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
