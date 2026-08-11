import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.config import get_settings
from app.security import hash_password
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def seed() -> None:
    engine = create_async_engine(get_settings().ddl_database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        async with session.begin():
            tenant_ids = [uuid4(), uuid4()]
            for index, tenant_id in enumerate(tenant_ids, start=1):
                await session.execute(
                    text("INSERT INTO tenants (id,name,slug) VALUES (:id,:name,:slug) ON CONFLICT (slug) DO NOTHING"),
                    {"id": tenant_id, "name": f"Dev Tenant {index}", "slug": f"dev-tenant-{index}"},
                )
                current = await session.execute(
                    text("SELECT id FROM tenants WHERE slug = :slug"),
                    {"slug": f"dev-tenant-{index}"},
                )
                resolved_id = UUID(str(current.scalar_one()))
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
                        "email": f"admin{index}@example.test",
                        "name": f"Dev Admin {index}",
                        "password": hash_password("DevOnly-ChangeMe-123!"),
                        "created": datetime.now(UTC),
                    },
                )
            await session.execute(
                text(
                    "INSERT INTO permissions (key,description) VALUES "
                    "('tenant:admin','Manage tenant users and roles'),"
                    "('audit:read','Read audit records'),('events:read','Read events'),"
                    "('incidents:write','Create and update incidents') "
                    "ON CONFLICT (key) DO NOTHING"
                )
            )
            await session.execute(
                text(
                    "INSERT INTO roles (tenant_id,name) "
                    "SELECT id, 'tenant_admin' FROM tenants "
                    "WHERE slug IN ('dev-tenant-1','dev-tenant-2') "
                    "ON CONFLICT (tenant_id,name) DO NOTHING"
                )
            )
            await session.execute(
                text(
                    "INSERT INTO role_permissions (tenant_id,role_id,permission_id) "
                    "SELECT r.tenant_id, r.id, p.id FROM roles r "
                    "JOIN permissions p ON p.key IN "
                    "('tenant:admin','audit:read','events:read','incidents:write') "
                    "WHERE r.name = 'tenant_admin' "
                    "ON CONFLICT DO NOTHING"
                )
            )
            await session.execute(
                text(
                    "INSERT INTO role_assignments (tenant_id,user_id,role_id) "
                    "SELECT u.tenant_id, u.id, r.id FROM users u "
                    "JOIN roles r ON r.tenant_id = u.tenant_id "
                    "WHERE r.name = 'tenant_admin' "
                    "ON CONFLICT DO NOTHING"
                )
            )
    print(
        "Seeded dev-tenant-1 and dev-tenant-2; credentials are "
        "admin1@example.test/admin2@example.test with password "
        "DevOnly-ChangeMe-123!"
    )
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
