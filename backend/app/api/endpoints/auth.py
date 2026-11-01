"""Authentication endpoints."""

import re
import uuid
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from loguru import logger
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.common import ser
from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import create_access_token, decode_access_token, get_password_hash, verify_password
from app.db.models import Organization, OrganizationMember, User
from app.services.audit import audit
from app.services.email import send_verification_email

router = APIRouter()

VERIFY_PURPOSE = "verify_email"


class RegisterIn(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    full_name: str | None = Field(default=None, max_length=200)
    password: str = Field(min_length=10, max_length=128)
    organization_name: str | None = Field(default=None, max_length=200)


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=2000)


class EmailIn(BaseModel):
    email: EmailStr


def _user_out(u: User):
    return ser(u, exclude=("hashed_password",))


def _verification_link(user: User) -> str:
    token = create_access_token(str(user.id), timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
                                extra={"purpose": VERIFY_PURPOSE, "email": user.email})
    return f"{settings.FRONTEND_URL.rstrip('/')}/verify-email?token={quote(token)}"


async def _send_verification(user: User) -> dict:
    """Emails the link. Without SMTP outside production, logs it and returns it so local setups still work."""
    link = _verification_link(user)
    sent = await send_verification_email(user.email, link)
    out: dict = {"verification_email_sent": sent}
    if not sent and settings.ENVIRONMENT != "production":
        logger.info(f"Email verification link for {user.email}: {link}")
        out["verification_url"] = link
    elif not sent:
        logger.error(f"Could not deliver the verification email to {user.email}; check the SMTP_* settings")
    return out


@router.post("/register", status_code=201)
async def register(body: RegisterIn, request: Request, db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(User).where((User.email == body.email.lower()) | (User.username == body.username)))).scalar_one_or_none():
        raise HTTPException(400, "Email or username already registered")
    verify = settings.email_verification_required
    user = User(email=body.email.lower(), username=body.username, full_name=body.full_name,
                hashed_password=get_password_hash(body.password), email_verified=not verify)
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
    demo_org_id = None
    if settings.DEMO_VIEWER_ON_REGISTER:
        # Read-only access to the seeded demo organization: visitors see real scan results at once.
        demo = (await db.execute(select(Organization).where(Organization.slug == "trace-demo"))).scalar_one_or_none()
        if demo:
            db.add(OrganizationMember(organization_id=demo.id, user_id=user.id, role="viewer"))
            demo_org_id = str(demo.id)
    await audit(db, "user.register", org_id=org.id, user=user, resource_type="user", resource_id=user.id, ip=request.client.host if request.client else None)
    out = {"user": _user_out(user), "organization": ser(org), "demo_organization_id": demo_org_id, "verification_required": verify}
    await db.commit()  # the account must exist before its verification link goes out
    if verify:
        out.update(await _send_verification(user))
    return out


@router.post("/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == form.username.lower()))).scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        await audit(db, "auth.login_failed", actor=form.username[:100], details={}, ip=request.client.host if request.client else None)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Inactive user")
    if settings.email_verification_required and not user.email_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, {
            "code": "email_not_verified",
            "message": "Verify your email address before signing in. Check your inbox for the verification link.",
        })
    await audit(db, "auth.login", user=user, ip=request.client.host if request.client else None)
    return {"access_token": create_access_token(str(user.id)), "token_type": "bearer"}


@router.post("/verify-email")
async def verify_email(body: TokenIn, request: Request, db: AsyncSession = Depends(get_db)):
    payload = decode_access_token(body.token)
    user = None
    if payload and payload.get("purpose") == VERIFY_PURPOSE:
        try:
            user = await db.get(User, uuid.UUID(payload["sub"]))
        except (KeyError, ValueError):
            user = None
    # The token is bound to the address it was sent to.
    if not user or user.email != payload.get("email"):
        raise HTTPException(400, "This verification link is invalid or has expired. Request a new one from the sign-in page.")
    if not user.email_verified:
        user.email_verified = True
        await audit(db, "user.email_verified", user=user, resource_type="user", resource_id=user.id,
                    ip=request.client.host if request.client else None)
    return {"verified": True, "email": user.email}


@router.post("/resend-verification", status_code=202)
async def resend_verification(body: EmailIn, db: AsyncSession = Depends(get_db)):
    # Same answer whether or not the account exists, so this cannot be used to probe for emails.
    out: dict = {"message": "If an unverified account exists for this email, a new verification link has been sent."}
    user = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one_or_none()
    if user and user.is_active and not user.email_verified:
        result = await _send_verification(user)
        if "verification_url" in result:
            out["verification_url"] = result["verification_url"]
    return out


@router.get("/me")
async def me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(OrganizationMember, Organization).join(Organization).where(OrganizationMember.user_id == user.id).order_by(OrganizationMember.created_at))).all()
    return {"user": _user_out(user), "organizations": [{**ser(o, include=("id", "name", "slug")), "role": m.role} for m, o in rows]}
