import os

PLACEHOLDER_DATABASE_URL = "postgresql+asyncpg://placeholder:placeholder@localhost/placeholder"

_security_database_url = os.environ.get("SECURITY_DATABASE_URL")
_security_owner_database_url = os.environ.get("SECURITY_OWNER_DATABASE_URL")

os.environ.setdefault("DATABASE_URL", _security_database_url or PLACEHOLDER_DATABASE_URL)
os.environ.setdefault("DDL_DATABASE_URL", _security_owner_database_url or PLACEHOLDER_DATABASE_URL)
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
os.environ.setdefault("S3_ENDPOINT", os.environ.get("MINIO_TEST_ENDPOINT", "http://localhost:9000"))
os.environ.setdefault("S3_ACCESS_KEY", "minioadmin")
os.environ.setdefault("S3_SECRET_KEY", "minioadmin")
os.environ.setdefault("S3_BUCKET", "cyberops-test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
