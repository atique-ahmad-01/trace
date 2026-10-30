"""
Background job dispatch.

Uses RQ when REDIS_URL is configured and reachable; otherwise runs jobs on an
in-process thread pool (each job gets its own event loop and DB sessions).
Job functions must be importable top-level coroutines taking simple arguments.
"""

import asyncio
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

from loguru import logger

from app.core.config import settings

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="trace-job")
_status_lock = threading.Lock()
_inproc_status: Dict[str, int] = {"running": 0, "completed": 0, "failed": 0}
_redis_ok: bool | None = None


def _resolve(path: str):
    mod, fn = path.rsplit(".", 1)
    return getattr(importlib.import_module(mod), fn)


def run_job_sync(path: str, *args: Any) -> None:
    """Entry point executed by RQ workers and the thread pool."""
    fn = _resolve(path)
    asyncio.run(_run_with_fresh_engine(fn, *args))


async def _run_with_fresh_engine(fn, *args):
    # Each event loop needs its own engine/connection pool.
    from app.core import database

    old_engine, old_maker = database.engine, database.async_session_maker
    database.engine = database._make_engine(settings.async_database_url)
    database.async_session_maker = database.async_sessionmaker(
        database.engine, class_=database.AsyncSession, expire_on_commit=False, autoflush=False
    )
    try:
        await fn(*args)
    finally:
        await database.engine.dispose()
        database.engine, database.async_session_maker = old_engine, old_maker


def _redis_available() -> bool:
    global _redis_ok
    if _redis_ok is not None:
        return _redis_ok
    if not settings.REDIS_URL:
        _redis_ok = False
        return False
    try:
        import redis

        redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1).ping()
        _redis_ok = True
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Redis unavailable ({e}); using in-process job runner")
        _redis_ok = False
    return _redis_ok


def backend_name() -> str:
    return "rq" if _redis_available() else "in-process"


def status() -> Dict[str, Any]:
    with _status_lock:
        return {"backend": backend_name(), **_inproc_status}


def enqueue(path: str, *args: Any) -> None:
    args = tuple(str(a) if not isinstance(a, (int, float, bool, type(None), dict, list)) else a for a in args)
    if settings.ENVIRONMENT == "test":
        return  # tests invoke job coroutines directly
    if _redis_available():
        import redis
        from rq import Queue

        q = Queue(settings.RQ_QUEUE_NAME, connection=redis.Redis.from_url(settings.REDIS_URL))
        q.enqueue(run_job_sync, path, *args, job_timeout=settings.JOB_TIMEOUT_SECONDS)
        return

    def _wrapped():
        with _status_lock:
            _inproc_status["running"] += 1
        try:
            run_job_sync(path, *args)
            key = "completed"
        except Exception:  # noqa: BLE001
            logger.exception(f"Job {path} failed")
            key = "failed"
        with _status_lock:
            _inproc_status["running"] -= 1
            _inproc_status[key] += 1

    _executor.submit(_wrapped)
