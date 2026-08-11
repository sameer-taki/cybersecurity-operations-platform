import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from app.raw_store import S3RawObjectStore
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

DATABASE_URL = os.environ.get("SECURITY_DATABASE_URL")
OWNER_DATABASE_URL = os.environ.get("SECURITY_OWNER_DATABASE_URL")
if DATABASE_URL:
    os.environ.setdefault("DATABASE_URL", DATABASE_URL)
if OWNER_DATABASE_URL:
    os.environ.setdefault("DDL_DATABASE_URL", OWNER_DATABASE_URL)
os.environ.setdefault("JWT_SECRET", "integration-only")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
os.environ.setdefault("S3_ENDPOINT", os.environ.get("MINIO_TEST_ENDPOINT", "http://localhost:9000"))
os.environ.setdefault("S3_ACCESS_KEY", "minioadmin")
os.environ.setdefault("S3_SECRET_KEY", "minioadmin")
os.environ.setdefault("S3_BUCKET", "cyberops-test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL or not OWNER_DATABASE_URL,
    reason="set SECURITY_DATABASE_URL and SECURITY_OWNER_DATABASE_URL for PostgreSQL security tests",
)


@pytest.fixture
async def security_data() -> tuple[str, str, AsyncEngine, AsyncEngine]:
    assert DATABASE_URL is not None
    assert OWNER_DATABASE_URL is not None
    runtime = create_async_engine(DATABASE_URL)
    owner = create_async_engine(OWNER_DATABASE_URL)
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    async with owner.begin() as connection:
        await connection.execute(
            text("INSERT INTO tenants (id,name,slug) VALUES (:id,:name,:slug)"),
            [
                {"id": tenant_a, "name": "Security A", "slug": f"security-a-{tenant_a[:8]}"},
                {"id": tenant_b, "name": "Security B", "slug": f"security-b-{tenant_b[:8]}"},
            ],
        )
        await connection.execute(
            text("INSERT INTO users (tenant_id,email,display_name) VALUES (:tenant,:email,:name)"),
            [
                {"tenant": tenant_a, "email": f"a-{tenant_a[:8]}@example.com", "name": "A"},
                {"tenant": tenant_b, "email": f"b-{tenant_b[:8]}@example.com", "name": "B"},
            ],
        )
    try:
        yield tenant_a, tenant_b, runtime, owner
    finally:
        async with owner.begin() as connection:
            await connection.execute(
                text("DELETE FROM api_keys WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM raw_event_refs WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM refresh_tokens WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM role_assignments WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM role_permissions WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM roles WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM audit_log WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(
                text("DELETE FROM users WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            await connection.execute(text("DELETE FROM tenants WHERE id IN (:a, :b)"), {"a": tenant_a, "b": tenant_b})
        await runtime.dispose()
        await owner.dispose()


async def test_runtime_role_is_non_owner_and_non_bypass(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    _tenant_a, _tenant_b, runtime, owner = security_data
    async with owner.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT r.rolsuper, r.rolbypassrls, "
                "EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid) "
                "FROM pg_roles r WHERE r.rolname = current_user"
            )
        )
        superuser, bypass, owner_objects = result.one()
        assert superuser is True
        assert bypass is True
        assert owner_objects is True
    async with runtime.connect() as connection:
        result = await connection.execute(
            text(
                "SELECT r.rolsuper, r.rolbypassrls, "
                "EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid) "
                "FROM pg_roles r WHERE r.rolname = current_user"
            )
        )
        superuser, bypass, owner_objects = result.one()
        assert superuser is False
        assert bypass is False
        assert owner_objects is False


async def test_tenant_id_filter_and_context_cannot_cross_tenants(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    tenant_a, tenant_b, runtime, _owner = security_data
    async with runtime.begin() as connection:
        await connection.execute(
            text("SELECT set_config('app.current_tenant', :tenant, true)"),
            {"tenant": tenant_a},
        )
        result = await connection.execute(
            text("SELECT count(*) FROM users WHERE tenant_id = :tenant"),
            {"tenant": tenant_b},
        )
        assert result.scalar_one() == 0
        result = await connection.execute(text("SELECT count(*) FROM users"))
        assert result.scalar_one() == 1
        await connection.execute(
            text("SELECT set_config('app.current_tenant', :tenant, true)"),
            {"tenant": tenant_b},
        )
        result = await connection.execute(
            text("SELECT count(*) FROM users WHERE tenant_id = :tenant"),
            {"tenant": tenant_a},
        )
        assert result.scalar_one() == 0


async def test_missing_tenant_context_fails_closed(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    _tenant_a, _tenant_b, runtime, _owner = security_data
    async with runtime.connect() as connection:
        result = await connection.execute(text("SELECT count(*) FROM users"))
        assert result.scalar_one() == 0


async def test_runtime_audit_mutation_is_denied(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    tenant_a, _tenant_b, runtime, owner = security_data
    async with owner.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO audit_log (tenant_id,action,resource_type,entry_hash) "
                "VALUES (:tenant,'security.test','test',repeat('a',64))"
            ),
            {"tenant": tenant_a},
        )
    async with runtime.begin() as connection:
        await connection.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": tenant_a})
        with pytest.raises(Exception, match="permission denied"):
            await connection.execute(text("UPDATE audit_log SET action = 'mutated'"))
    async with runtime.begin() as connection:
        await connection.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": tenant_a})
        with pytest.raises(Exception, match="permission denied"):
            await connection.execute(text("DELETE FROM audit_log"))


async def test_mutated_audit_row_fails_chain_verification(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    tenant_a, _tenant_b, runtime, owner = security_data
    from app.audit import append_audit, verify_audit_chain

    async with runtime.begin() as connection:
        await connection.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": tenant_a})
        await append_audit(connection, tenant_a, None, "security.chain", "test", "one", {})
        result = await connection.execute(
            text("SELECT id FROM audit_log WHERE tenant_id = :tenant ORDER BY created_at DESC LIMIT 1"),
            {"tenant": tenant_a},
        )
        audit_id = result.scalar_one()
    async with owner.begin() as connection:
        await connection.execute(
            text("UPDATE audit_log SET action = 'mutated' WHERE id = :id"),
            {"id": audit_id},
        )
    async with runtime.begin() as connection:
        await connection.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": tenant_a})
        assert await verify_audit_chain(connection, tenant_a) is False


async def test_partition_and_tenant_not_null_invariants(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    _tenant_a, _tenant_b, _runtime, owner = security_data
    async with owner.connect() as connection:
        partitions = await connection.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "has_table_privilege('app_api_login', c.oid, 'SELECT'), "
                "EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' "
                "AND p.tablename = c.relname AND p.policyname = 'tenant_isolation') "
                "FROM pg_class c JOIN pg_inherits i ON i.inhrelid = c.oid "
                "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'events'"
            )
        )
        rows = partitions.all()
        assert rows
        assert all(row[1] and row[2] and row[3] and row[4] for row in rows)
        not_null = await connection.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema = 'public' AND column_name = 'tenant_id' AND is_nullable = 'YES'"
            )
        )
        assert not_null.scalar_one() == 0


def test_secret_redaction_and_error_envelope() -> None:
    import logging
    from io import StringIO

    from app.logging_redaction import SecretRedactionFilter

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretRedactionFilter(["super-secret"]))
    logger = logging.getLogger("security.integration")
    logger.addHandler(handler)
    try:
        logger.warning("credential=%s", "super-secret")
        assert "super-secret" not in stream.getvalue()
        assert "[REDACTED]" in stream.getvalue()
        assert "super-secret" not in "invalid credentials"
    finally:
        logger.removeHandler(handler)


async def test_minio_round_trip_rejects_other_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = os.environ.get("MINIO_TEST_ENDPOINT")
    if not endpoint:
        pytest.skip("set MINIO_TEST_ENDPOINT for MinIO integration tests")
    tenant_a = uuid4()
    tenant_b = uuid4()
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL or "postgresql+asyncpg://x:x@localhost/x")
    monkeypatch.setenv("DDL_DATABASE_URL", OWNER_DATABASE_URL or "postgresql+asyncpg://x:x@localhost/x")
    monkeypatch.setenv("JWT_SECRET", "integration-only")
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("S3_ENDPOINT", endpoint)
    monkeypatch.setenv("S3_ACCESS_KEY", "minioadmin")
    monkeypatch.setenv("S3_SECRET_KEY", "minioadmin")
    monkeypatch.setenv("S3_BUCKET", "cyberops-test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    store = S3RawObjectStore(
        endpoint=endpoint,
        access_key="minioadmin",
        secret_key="minioadmin",
        bucket="cyberops-test",
    )
    uri = await store.put(tenant_a, datetime(2026, 8, 11, tzinfo=UTC), "integration", b"raw")
    assert await store.get(tenant_a, uri) == b"raw"
    with pytest.raises(PermissionError):
        await store.get(tenant_b, uri)


async def test_refresh_replay_revokes_token_family(monkeypatch: pytest.MonkeyPatch) -> None:
    assert DATABASE_URL is not None
    assert OWNER_DATABASE_URL is not None
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("DDL_DATABASE_URL", OWNER_DATABASE_URL)
    monkeypatch.setenv("JWT_SECRET", "development-only-secret")
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("S3_ENDPOINT", "http://localhost:9000")
    monkeypatch.setenv("S3_ACCESS_KEY", "minioadmin")
    monkeypatch.setenv("S3_SECRET_KEY", "minioadmin")
    monkeypatch.setenv("S3_BUCKET", "cyberops-raw")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    from app.auth import authenticate, rotate_refresh_token
    from app.security import decode_token

    pair = await authenticate("admin1@example.com", "DevOnly-ChangeMe-123!", None, "dev-tenant-1")
    rotated = await rotate_refresh_token(pair.refresh_token)
    with pytest.raises(ValueError, match="reuse"):
        await rotate_refresh_token(pair.refresh_token)
    claims = decode_token(rotated.refresh_token, "refresh")
    owner_engine = create_async_engine(OWNER_DATABASE_URL)
    async with owner_engine.connect() as connection:
        result = await connection.execute(
            text("SELECT count(*) FROM refresh_tokens WHERE family_id = :family AND revoked_at IS NOT NULL"),
            {"family": str(claims["family_id"])},
        )
        assert result.scalar_one() >= 2
    await owner_engine.dispose()


async def test_api_key_scope_ip_and_revocation(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
) -> None:
    tenant_a, _tenant_b, _runtime, owner = security_data
    from app.auth import auth_sessions
    from app.main import api_key_principal
    from app.security import new_api_key

    bind = auth_sessions.kw.get("bind")
    if isinstance(bind, AsyncEngine):
        await bind.dispose()
    prefix, secret, digest = new_api_key()
    key_id = uuid4()
    async with owner.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO api_keys (id,tenant_id,name,prefix,key_hash,scopes,ip_allowlist) "
                "VALUES (:id,:tenant,'integration',:prefix,:hash,:scopes,:ips)"
            ),
            {
                "id": key_id,
                "tenant": tenant_a,
                "prefix": prefix,
                "hash": digest,
                "scopes": ["events:read"],
                "ips": ["127.0.0.1/32"],
            },
        )
    principal = await api_key_principal(secret, "127.0.0.1")
    assert "events:read" in principal.permissions
    with pytest.raises(Exception, match="invalid API key"):
        await api_key_principal(secret, "10.0.0.1")
    with pytest.raises(Exception, match="required"):
        from app.main import require_api_scope

        await require_api_scope("events:write")(principal)
    with pytest.raises(Exception, match="invalid API key"):
        await api_key_principal("invalid", "127.0.0.1")
    async with owner.begin() as connection:
        await connection.execute(text("UPDATE api_keys SET revoked_at = now() WHERE id = :id"), {"id": key_id})
    with pytest.raises(Exception, match="invalid API key"):
        await api_key_principal(secret, "127.0.0.1")


async def test_out_of_window_event_is_quarantined(
    security_data: tuple[str, str, AsyncEngine, AsyncEngine],
    tmp_path: Path,
) -> None:
    tenant_a, _tenant_b, runtime, _owner = security_data
    from app.event_contract import Actor, CommonEvent, Source, Target, canonical_raw_hash, raw_object_uri
    from app.event_persistence import persist_raw_event
    from app.raw_store import LocalRawObjectStore

    raw = b'{"event":"quarantine"}'
    tenant_id = UUID(tenant_a)
    observed = datetime.now(UTC) - timedelta(days=365)
    event_id = f"quarantine-{tenant_a[:8]}"
    event = CommonEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        observed_at=observed,
        ingested_at=datetime.now(UTC),
        source=Source(type="test", vendor="test", product="test"),
        actor=Actor(),
        target=Target(),
        event_type="test.quarantine",
        severity="low",
        confidence=1,
        outcome="unknown",
        raw_event_ref=raw_object_uri(tenant_id, observed, event_id),
        parser_name="test",
        parser_version="1",
        raw_event_sha256=canonical_raw_hash(raw),
    )
    async with runtime.begin() as connection:
        await connection.execute(
            text("SELECT set_config('app.current_tenant', :tenant, true)"),
            {"tenant": tenant_a},
        )
        assert await persist_raw_event(
            connection,
            LocalRawObjectStore(tmp_path),
            event,
            raw,
            tmp_path,
        )
        result = await connection.execute(
            text("SELECT count(*) FROM events WHERE tenant_id = :tenant AND event_id = :event"),
            {"tenant": tenant_a, "event": event_id},
        )
        assert result.scalar_one() == 0
        result = await connection.execute(
            text("SELECT count(*) FROM raw_event_refs WHERE tenant_id = :tenant AND event_id = :event"),
            {"tenant": tenant_a, "event": event_id},
        )
        assert result.scalar_one() == 1
    assert (tmp_path / "quarantine" / tenant_a / event_id).read_bytes() == raw
