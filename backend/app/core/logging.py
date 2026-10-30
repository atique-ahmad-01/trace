"""
Logging Configuration

Structured logging via loguru with secret redaction. Standard library logging
is intercepted so third-party logs share the same sink and redaction.
"""

import logging
import re
import sys

from loguru import logger

from app.core.config import settings

# Each pattern captures a prefix to keep (group 1) followed by the secret.
_SECRET_PATTERNS = [
    re.compile(r"()\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"()\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"()\bsk-[A-Za-z0-9\-_]{16,}"),
    re.compile(r"()\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-_\.=]{12,}"),
    re.compile(r"(?i)((?:password|secret|token|api[_-]?key)[\"']?\s*[:=]\s*[\"']?)[^\s\"',}]{4,}"),
    re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+(?=@)"),
]


def redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(1) + "[REDACTED]", text)
    return text


def _patch(record):
    record["message"] = redact(record["message"])


class InterceptHandler(logging.Handler):
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        logger.opt(depth=6, exception=record.exc_info).log(level, record.getMessage())


def setup_logging() -> None:
    logger.remove()
    serialize = settings.ENVIRONMENT == "production"
    logger.configure(patcher=_patch)
    logger.add(
        sys.stdout,
        level=settings.LOG_LEVEL,
        serialize=serialize,
        colorize=not serialize,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <7}</level> | <cyan>{name}</cyan> | {message}",
    )
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for name in ["uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore", "aiosqlite"]:
        logging.getLogger(name).setLevel(logging.WARNING)
