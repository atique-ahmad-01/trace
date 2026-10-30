"""Organization, membership, credential and audit endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import Page, paginate, ser
from app.core.database import get_db
from app.core.deps import OrgContext, get_org_context, require_role
from app.core.security import encrypt_secret
from app.db.models import AuditLog, Credential, GitHubInstallation, OrganizationMember, User
from app.services.audit import audit

router = APIRouter()


@router.get("/current")
async def current(ctx: OrgContext = Depends(get_org_context), db: AsyncSession = Depends(get_db)):
    members = (await db.execute(select(OrganizationMember, User).join(User).where(OrganizationMember.organization_id == ctx.org_id))).all()
    installs = (await db.execute(select(GitHubInstallation).where(GitHubInstallation.organization_id == ctx.org_id))).scalars().all()
    return {"organization": ser(ctx.org), "role": ctx.role,
            "members": [{"user_id": str(u.id), "email": u.email, "username": u.username, "role": m.role} for m, u in members],
            "github_installations": [ser(i) for i in installs]}


class MemberIn(BaseModel):
    email: EmailStr
    role: str = Field(pattern="^(viewer|member|admin)$")


@router.post("/current/members", status_code=201)
async def add_member(body: MemberIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User must register first")
    if (await db.execute(select(OrganizationMember).where(OrganizationMember.organization_id == ctx.org_id, OrganizationMember.user_id == user.id))).scalar_one_or_none():
        raise HTTPException(400, "Already a member")
    db.add(OrganizationMember(organization_id=ctx.org_id, user_id=user.id, role=body.role))
    await audit(db, "org.member_added", org_id=ctx.org_id, user=ctx.user, resource_type="user", resource_id=user.id, details={"role": body.role})
    return {"ok": True}


class CredentialIn(BaseModel):
    kind: str = Field(pattern="^(github_token)$")
    name: str = Field(default="default", max_length=100)
    value: str = Field(min_length=8, max_length=500)


@router.get("/current/credentials")
async def list_credentials(ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Credential).where(Credential.organization_id == ctx.org_id))).scalars().all()
    return [ser(c, exclude=("encrypted_value",)) for c in rows]


@router.put("/current/credentials")
async def set_credential(body: CredentialIn, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    cred = (await db.execute(select(Credential).where(Credential.organization_id == ctx.org_id, Credential.kind == body.kind,
                                                      Credential.name == body.name))).scalar_one_or_none()
    if not cred:
        cred = Credential(organization_id=ctx.org_id, kind=body.kind, name=body.name, encrypted_value="")
        db.add(cred)
    cred.encrypted_value = encrypt_secret(body.value.strip())
    cred.last4 = body.value.strip()[-4:]
    await audit(db, "credential.set", org_id=ctx.org_id, user=ctx.user, resource_type="credential", details={"kind": body.kind, "name": body.name})
    await db.flush()
    return ser(cred, exclude=("encrypted_value",))


@router.delete("/current/credentials/{cred_id}")
async def delete_credential(cred_id: uuid.UUID, ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    cred = await db.get(Credential, cred_id)
    if not cred or cred.organization_id != ctx.org_id:
        raise HTTPException(404, "Credential not found")
    await db.delete(cred)
    await audit(db, "credential.delete", org_id=ctx.org_id, user=ctx.user, resource_type="credential", resource_id=cred_id)
    return {"ok": True}


@router.get("/current/audit")
async def audit_log(action: str | None = None, page: Page = Depends(), ctx: OrgContext = Depends(require_role("admin")), db: AsyncSession = Depends(get_db)):
    q = select(AuditLog).where(AuditLog.organization_id == ctx.org_id)
    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    return await paginate(db, q.order_by(AuditLog.created_at.desc()), page)
