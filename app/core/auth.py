from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.models.models import User

logger = logging.getLogger("auth")

# JWT & Cryptographic Secret
SECRET_KEY = getattr(settings, "jwt_secret", "hunter_aja_super_secret_jwt_key_2026_pentest_secure")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 86400 * 7  # 7 days


# --------------------------------------------------------------------------
# Password Hashing (PBKDF2-HMAC-SHA256 with 600,000 iterations)
# --------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash password using salt + PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        600_000,
    )
    return f"pbkdf2_sha256$600000${salt}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time password verification."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        expected_hex = parts[3]
        key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(key.hex(), expected_hex)
    except Exception:
        return False


# --------------------------------------------------------------------------
# Standalone JWT Engine (HS256)
# --------------------------------------------------------------------------
def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_access_token(user_id: str, username: str, role: str, expires_in: int = JWT_EXPIRATION_SECONDS) -> str:
    """Create a signed HS256 JWT access token."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
    }

    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    signature = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode HS256 JWT access token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_sig = _b64_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, provided_sig):
            return None

        payload_bytes = _b64_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))

        if payload.get("exp", 0) < time.time():
            return None  # Token expired

        return payload
    except Exception as e:
        logger.debug("Token decode error: %s", e)
        return None


# --------------------------------------------------------------------------
# FastAPI Dependency Injectors
# --------------------------------------------------------------------------
async def get_optional_user(
    authorization: Optional[str] = Header(None),
    token_cookie: Optional[str] = Cookie(None, alias="auth_token"),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Extract and authenticate user if token is provided; else return None."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif token_cookie:
        token = token_cookie.strip()

    if not token:
        return None

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None

    user_id = payload["sub"]
    user = await db.get(User, user_id)
    if user and user.is_active:
        return user
    return None


async def get_current_user(
    user: Optional[User] = Depends(get_optional_user),
) -> User:
    """Ensure caller is authenticated."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi diperlukan. Silakan login terlebih dahulu.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_user_role(
    user: User = Depends(get_current_user),
) -> User:
    """
    Ensure user has 'user' role for scanning activities.
    Admin accounts are strictly monitoring-only to prevent unauthorized scanning from oversight credentials.
    """
    if user.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akun Administrator hanya memiliki akses Pemantauan (Monitoring-Only) dan tidak dapat memulai pemindaian langsung. Silakan gunakan akun user.",
        )
    return user


async def require_admin_role(
    user: User = Depends(get_current_user),
) -> User:
    """Ensure user has 'admin' role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses ditolak. Fitur ini hanya dapat diakses oleh Administrator.",
        )
    return user
