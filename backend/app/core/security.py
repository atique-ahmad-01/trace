"""
Security Utilities

Password hashing, JWT tokens, credential encryption and webhook signature checks.
"""

import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    if not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode()[:72], hashed_password.encode())
    except ValueError:
        return False


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None, extra: Optional[Dict[str, Any]] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + (expires_delta or timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


def _fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()).decode()
    return Fernet(key.encode())


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_secret(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def verify_github_webhook_signature(payload: bytes, signature: Optional[str], secret: str) -> bool:
    if not signature or not signature.startswith("sha256=") or not secret:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.split("=", 1)[1])
