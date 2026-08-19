import os

import pytest
from app.config import get_settings
from app.db import engine
from conftest import PLACEHOLDER_DATABASE_URL
from sqlalchemy import make_url


def test_settings_match_process_environment() -> None:
    settings = get_settings()
    assert settings.database_url == os.environ["DATABASE_URL"]
    assert settings.ddl_database_url == os.environ["DDL_DATABASE_URL"]


def test_engine_uses_security_database_when_configured() -> None:
    security_database_url = os.environ.get("SECURITY_DATABASE_URL")
    if not security_database_url:
        pytest.skip("set SECURITY_DATABASE_URL to check integration engine wiring")
    assert engine.url == make_url(security_database_url)
    assert engine.url != make_url(PLACEHOLDER_DATABASE_URL)
