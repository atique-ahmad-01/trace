"""
Request dependencies: authentication and organization scoping.
"""

import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token
from app.db.models import Organization, OrganizationMember, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ROLE_RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    try:
        user_id = uuid.UUID(payload["sub"])
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token subject")
    user = await db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


@dataclass
class OrgContext:
    user: User
    org: Organization
    role: str

    @property
    def org_id(self) -> uuid.UUID:
        return self.org.id

    def require(self, min_role: str) -> None:
        if ROLE_RANK.get(self.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires {min_role} role")


async def get_org_context(
    x_organization_id: Optional[str] = Header(default=None),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> OrgContext:
    """Resolve the active organization (X-Organization-Id header, else first membership)."""
    q = select(OrganizationMember, Organization).join(Organization).where(OrganizationMember.user_id == user.id)
    if x_organization_id:
        try:
            q = q.where(Organization.id == uuid.UUID(x_organization_id))
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid X-Organization-Id")
    row = (await db.execute(q.order_by(OrganizationMember.created_at).limit(1))).first()
    if not row:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "No access to organization")
    member, org = row
    return OrgContext(user=user, org=org, role=member.role)


def require_role(min_role: str):
    async def _dep(ctx: OrgContext = Depends(get_org_context)) -> OrgContext:
        ctx.require(min_role)
        return ctx

    return _dep
