"""Audit trail helper."""

import uuid
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


async def audit(
    db: AsyncSession,
    action: str,
    *,
    org_id: Optional[uuid.UUID] = None,
    user=None,
    actor: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Any = None,
    details: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> None:
    db.add(
        AuditLog(
            organization_id=org_id,
            user_id=getattr(user, "id", None),
            actor=actor or getattr(user, "email", None) or "system",
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            details=details or {},
            ip_address=ip,
        )
    )
