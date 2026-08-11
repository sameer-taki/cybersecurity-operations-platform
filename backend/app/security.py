import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from typing import Final, cast
from uuid import UUID, uuid4

import jwt
import pyotp
from app.config import get_settings
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet

password_hasher: Final[PasswordHasher] = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16
)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hasher.verify(encoded, password)
    except (VerifyMismatchError, VerificationError):
        return False


def _fernet() -> Fernet:
    raw = get_settings().totp_encryption_key.encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def encrypt_totp_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_totp_secret(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_urlsafe(10) for _ in range(count)]


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def issue_access_token(user_id: UUID, tenant_id: UUID, permissions: list[str]) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "permissions": permissions,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_minutes),
        "iss": settings.jwt_issuer,
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def issue_refresh_token(user_id: UUID, tenant_id: UUID, family_id: UUID) -> tuple[str, datetime]:
    settings = get_settings()
    expiry = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_days)
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "family_id": str(family_id),
        "iat": datetime.now(UTC),
        "exp": expiry,
        "iss": settings.jwt_issuer,
        "type": "refresh",
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256"), expiry


def decode_token(value: str, expected_type: str) -> dict[str, object]:
    settings = get_settings()
    decoded = jwt.decode(value, settings.jwt_secret, algorithms=["HS256"], issuer=settings.jwt_issuer)
    if decoded.get("type") != expected_type:
        raise ValueError("invalid token type")
    return cast(dict[str, object], decoded)


def new_api_key() -> tuple[str, str, str]:
    value = f"cop_{secrets.token_urlsafe(32)}"
    return value[:12], value, hash_token(value)


def ip_allowed(address: str, allowlist: list[str] | None) -> bool:
    if not allowlist:
        return True
    candidate = ip_address(address)
    return any(candidate in ip_network(item) if "/" in item else candidate == ip_address(item) for item in allowlist)
