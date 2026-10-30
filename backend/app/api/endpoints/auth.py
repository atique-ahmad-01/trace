"""Authentication endpoints."""

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import ser
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.models import Organization, OrganizationMember, User
from app.services.audit import audit

router = APIRouter()


class RegisterIn(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    full_name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=10, max_length=128)
    organization_name: str | None = Field(default=None, max_length=200)


def _user_out(u: User):
    return ser(u, exclude=("hashed_password",))


@router.post("/register", status_code=201)
async def register(body: RegisterIn, request: Request, db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(User).where((User.email == body.email.lower()) | (User.username == body.username)))).scalar_one_or_none():
        raise HTTPException(400, "Email or username already registered")
    user = User(email=body.email.lower(), username=body.username, full_name=body.full_name, hashed_password=get_password_hash(body.password))
    db.add(user)
    await db.flush()
    name = body.organization_name or f"{body.username}'s organization"
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60] or "org"
    while (await db.execute(select(Organization).where(Organization.slug == slug))).scalar_one_or_none():
        slug = f"{slug}-{user.id.hex[:4]}"
    org = Organization(name=name, slug=slug)
    db.add(org)
    await db.flush()
    db.add(OrganizationMember(organization_id=org.id, user_id=user.id, role="owner"))
    await audit(db, "user.register", org_id=org.id, user=user, resource_type="user", resource_id=user.id, ip=request.client.host if request.client else None)
    return {"user": _user_out(user), "organization": ser(org)}


@router.post("/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form.username.lower()))).scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        await audit(db, "auth.login_failed", actor=form.username[:100], details={}, ip=request.client.host if request.client else None)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Inactive user")
    await audit(db, "auth.login", user=user, ip=request.client.host if request.client else None)
    return {"access_token": create_access_token(str(user.id)), "token_type": "bearer"}


@router.get("/me")
async def me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(OrganizationMember, Organization).join(Organization).where(OrganizationMember.user_id == user.id))).all()
    return {"user": _user_out(user), "organizations": [{**ser(o, include=("id", "name", "slug")), "role": m.role} for m, o in rows]}
