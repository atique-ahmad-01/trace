"""Shared API helpers: serialization, pagination, org-scoped lookups."""

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, Optional, Type

from fastapi import HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


def ser(obj, exclude: Iterable[str] = (), include: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    if obj is None:
        return None
    cols = [c.key for c in obj.__table__.columns]
    if include:
        cols = [c for c in cols if c in include]
    out = {}
    for c in cols:
        if c in exclude:
            continue
        v = getattr(obj, c)
        if isinstance(v, uuid.UUID):
            v = str(v)
        elif isinstance(v, datetime):
            v = v.isoformat()
        elif isinstance(v, enum.Enum):
            v = v.value
        out[c] = v
    return out


class Page:
    def __init__(self, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200)):
        self.page, self.page_size = page, page_size


async def paginate(db: AsyncSession, stmt, page: Page, mapper=ser) -> Dict[str, Any]:
    total = (await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar()
    rows = (await db.execute(stmt.offset((page.page - 1) * page.page_size).limit(page.page_size))).all()
    items = [mapper(*r) if len(r) > 1 else mapper(r[0]) for r in rows]
    return {"items": items, "total": total, "page": page.page, "page_size": page.page_size, "pages": (total + page.page_size - 1) // page.page_size}


async def get_owned(db: AsyncSession, model: Type, obj_id: uuid.UUID, org_id: uuid.UUID, name: str = "Resource"):
    obj = await db.get(model, obj_id)
    if not obj or getattr(obj, "organization_id", None) != org_id:
        raise HTTPException(404, f"{name} not found")
    return obj
