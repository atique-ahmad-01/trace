"""Sign-up requires email verification before the first sign-in."""

from datetime import timedelta

import pytest

from app.core.security import create_access_token

pytestmark = pytest.mark.asyncio

PW = "correct-horse-battery"


async def _signup(client, name):
    r = await client.post("/api/v1/auth/register", json={"email": f"{name}@example.com", "username": name, "password": PW})
    assert r.status_code == 201, r.text
    return r.json()


async def _login(client, name):
    return await client.post("/api/v1/auth/login", data={"username": f"{name}@example.com", "password": PW})


async def test_register_does_not_sign_in_and_blocks_login_until_verified(client):
    body = await _signup(client, "unverified")
    assert "access_token" not in body
    assert body["verification_required"] is True
    assert body["user"]["email_verified"] is False
    assert "/verify-email?token=" in body["verification_url"]

    r = await _login(client, "unverified")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "email_not_verified"

    token = body["verification_url"].split("token=", 1)[1]
    # A verification token is not a session token.
    assert (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})).status_code == 401

    r = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200 and r.json()["verified"] is True
    assert (await client.post("/api/v1/auth/verify-email", json={"token": token})).status_code == 200  # idempotent

    r = await _login(client, "unverified")
    assert r.status_code == 200, r.text
    me = (await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})).json()
    assert me["user"]["email_verified"] is True


async def test_wrong_password_does_not_reveal_verification_state(client):
    await _signup(client, "unverified2")
    r = await client.post("/api/v1/auth/login", data={"username": "unverified2@example.com", "password": "wrong-password-1"})
    assert r.status_code == 401


async def test_invalid_and_foreign_tokens_rejected(client):
    body = await _signup(client, "badtoken")
    assert (await client.post("/api/v1/auth/verify-email", json={"token": "not-a-real-token"})).status_code == 400
    user_id = body["user"]["id"]
    # A session token for the user is not a verification token.
    assert (await client.post("/api/v1/auth/verify-email", json={"token": create_access_token(user_id)})).status_code == 400
    expired = create_access_token(user_id, timedelta(seconds=-1), extra={"purpose": "verify_email", "email": "badtoken@example.com"})
    assert (await client.post("/api/v1/auth/verify-email", json={"token": expired})).status_code == 400
    other_email = create_access_token(user_id, extra={"purpose": "verify_email", "email": "someone@example.com"})
    assert (await client.post("/api/v1/auth/verify-email", json={"token": other_email})).status_code == 400
    assert (await _login(client, "badtoken")).status_code == 403


async def test_resend_verification(client):
    await _signup(client, "resend")
    r = await client.post("/api/v1/auth/resend-verification", json={"email": "resend@example.com"})
    assert r.status_code == 202
    token = r.json()["verification_url"].split("token=", 1)[1]
    assert (await client.post("/api/v1/auth/verify-email", json={"token": token})).status_code == 200
    assert (await _login(client, "resend")).status_code == 200
    # Verified or unknown accounts get the same generic answer and no link.
    for email in ("resend@example.com", "nobody-here@example.com"):
        r = await client.post("/api/v1/auth/resend-verification", json={"email": email})
        assert r.status_code == 202 and "verification_url" not in r.json()


async def test_verification_can_be_disabled(client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "EMAIL_VERIFICATION_REQUIRED", False)
    body = await _signup(client, "noverify")
    assert body["verification_required"] is False and "verification_url" not in body
    assert (await _login(client, "noverify")).status_code == 200
