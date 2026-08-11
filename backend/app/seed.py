import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.config import get_settings
from app.security import hash_password
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def seed() -> None:
    settings = get_settings()
    ddl_engine = create_async_engine(settings.ddl_database_url)
    platform_engine = create_async_engine(settings.platform_database_url or settings.database_url)
    runtime_engine = create_async_engine(settings.database_url)
    platform_factory = async_sessionmaker(platform_engine, expire_on_commit=False)
    runtime_factory = async_sessionmaker(runtime_engine, expire_on_commit=False)
    tenant_ids: list[UUID] = []
    async with platform_factory() as session:
        async with session.begin():
            for index in range(1, 3):
                tenant_id = uuid4()
                await session.execute(
                    text("INSERT INTO tenants (id,name,slug) VALUES (:id,:name,:slug) ON CONFLICT (slug) DO NOTHING"),
                    {"id": tenant_id, "name": f"Dev Tenant {index}", "slug": f"dev-tenant-{index}"},
                )
                current = await session.execute(
                    text("SELECT id FROM tenants WHERE slug = :slug"),
                    {"slug": f"dev-tenant-{index}"},
                )
                resolved_id = UUID(str(current.scalar_one()))
                tenant_ids.append(resolved_id)
    async with ddl_engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO permissions (key,description) VALUES "
                "('tenant:admin','Manage tenant users and roles'),"
                "('audit:read','Read audit records'),('events:read','Read events'),"
                "('incidents:write','Create and update incidents') "
                "ON CONFLICT (key) DO NOTHING"
            )
        )
    for index, resolved_id in enumerate(tenant_ids, start=1):
        async with runtime_factory() as session:
            async with session.begin():
                await session.execute(
                    text("SELECT set_config('app.current_tenant', :tenant, true)"),
                    {"tenant": str(resolved_id)},
                )
                await session.execute(
                    text(
                        "INSERT INTO users (tenant_id,email,display_name,password_hash,created_at) "
                        "VALUES (:tenant,:email,:name,:password,:created) "
                        "ON CONFLICT (tenant_id,email) DO NOTHING"
                    ),
                    {
                        "tenant": str(resolved_id),
                        "email": f"admin{index}@example.com",
                        "name": f"Dev Admin {index}",
                        "password": hash_password("DevOnly-ChangeMe-123!"),
                        "created": datetime.now(UTC),
                    },
                )
                await session.execute(
                    text(
                        "INSERT INTO roles (tenant_id,name) VALUES (:tenant,'tenant_admin') "
                        "ON CONFLICT (tenant_id,name) DO NOTHING"
                    ),
                    {"tenant": resolved_id},
                )
                await session.execute(
                    text(
                        "INSERT INTO role_permissions (tenant_id,role_id,permission_id) "
                        "SELECT :tenant, r.id, p.id FROM roles r "
                        "JOIN permissions p ON p.key IN "
                        "('tenant:admin','audit:read','events:read','incidents:write') "
                        "WHERE r.tenant_id = :tenant AND r.name = 'tenant_admin' "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {"tenant": resolved_id},
                )
                await session.execute(
                    text(
                        "INSERT INTO role_assignments (tenant_id,user_id,role_id) "
                        "SELECT :tenant, u.id, r.id FROM users u "
                        "JOIN roles r ON r.tenant_id = u.tenant_id "
                        "WHERE u.tenant_id = :tenant AND r.name = 'tenant_admin' "
                        "AND u.email = :email "
                        "AND NOT EXISTS ("
                        "SELECT 1 FROM role_assignments existing "
                        "WHERE existing.tenant_id = :tenant AND existing.user_id = u.id "
                        "AND existing.role_id = r.id)"
                    ),
                    {"tenant": resolved_id, "email": f"admin{index}@example.com"},
                )
    print(
        "Seeded dev-tenant-1 and dev-tenant-2; credentials are "
        "admin1@example.com/admin2@example.com with password "
        "DevOnly-ChangeMe-123!"
    )
    await ddl_engine.dispose()
    await platform_engine.dispose()
    await runtime_engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
