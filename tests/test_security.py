import os
from uuid import uuid4

os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("DDL_DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("S3_ENDPOINT", "http://localhost")
os.environ.setdefault("S3_ACCESS_KEY", "x")
os.environ.setdefault("S3_SECRET_KEY", "x")
os.environ.setdefault("S3_BUCKET", "x")
os.environ.setdefault("REDIS_URL", "redis://localhost")

from app.event_contract import dedup_key, raw_object_uri, validate_raw_object_uri
from app.rbac import attributes_match
from app.security import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    hash_password,
    issue_access_token,
    new_api_key,
    new_totp_secret,
    verify_password,
    verify_totp,
)


def test_password_hash_and_verify() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded != "correct horse battery staple"
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)


def test_totp_secret_encryption_and_code() -> None:
    secret = new_totp_secret()
    assert decrypt_totp_secret(encrypt_totp_secret(secret)) == secret
    import pyotp

    assert verify_totp(secret, pyotp.TOTP(secret).now())


def test_token_and_api_key_are_random() -> None:
    tenant_id = uuid4()
    user_id = uuid4()
    assert issue_access_token(user_id, tenant_id, ["events:read"])
    prefix, value, digest = new_api_key()
    assert value.startswith("cop_")
    assert value[:12] == prefix
    assert len(digest) == 64


def test_event_dedup_and_tenant_uri() -> None:
    tenant_id = uuid4()
    from datetime import UTC, datetime

    observed = datetime(2026, 8, 11, tzinfo=UTC)
    key = dedup_key(tenant_id, "connector", b"raw", "source-1", observed)
    assert key == f"{tenant_id}:connector:source-1"
    uri = raw_object_uri(tenant_id, observed, "evt-1")
    assert validate_raw_object_uri(uri, tenant_id)
    assert not validate_raw_object_uri(uri, uuid4())


def test_rbac_attribute_conditions_match_and_deny() -> None:
    condition = {"department": "security", "clearance": "high"}
    assert attributes_match(condition, {"department": "security", "clearance": "high", "region": "pacific"})
    assert not attributes_match(condition, {"department": "finance", "clearance": "high"})
    assert not attributes_match(condition, {"department": "security"})
