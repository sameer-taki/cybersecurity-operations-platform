from collections.abc import Iterator

import pytest
from app.config import get_settings

PLACEHOLDER_ENV: dict[str, str] = {
    "JWT_SECRET": "test-secret",
    "TOTP_ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef",
    "DATABASE_URL": "postgresql+asyncpg://x:x@localhost/x",
    "DDL_DATABASE_URL": "postgresql+asyncpg://x:x@localhost/x",
    "S3_ENDPOINT": "http://localhost",
    "S3_ACCESS_KEY": "x",
    "S3_SECRET_KEY": "x",
    "S3_BUCKET": "x",
    "REDIS_URL": "redis://localhost",
}


@pytest.fixture(autouse=True)
def reset_settings_cache() -> Iterator[None]:
    """Keep cached settings from crossing test boundaries with another test's environment."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def placeholder_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide throwaway configuration for tests that never touch the real services."""
    for key, value in PLACEHOLDER_ENV.items():
        monkeypatch.setenv(key, value)
