from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from app.config import get_settings
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

settings = get_settings()
engine: Final[AsyncEngine] = create_async_engine(settings.database_url, pool_pre_ping=True)
session_factory: Final[async_sessionmaker[AsyncSession]] = async_sessionmaker(engine, expire_on_commit=False)
platform_engine: Final[AsyncEngine] = create_async_engine(
    settings.platform_database_url or settings.database_url,
    pool_pre_ping=True,
)
platform_session_factory: Final[async_sessionmaker[AsyncSession]] = async_sessionmaker(
    platform_engine, expire_on_commit=False
)


@asynccontextmanager
async def tenant_transaction(tenant_id: str) -> AsyncIterator[AsyncSession]:
    if not tenant_id:
        raise ValueError("tenant context is required")
    async with session_factory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": tenant_id},
            )
            yield session


async def require_tenant_context(session: AsyncSession) -> None:
    result = await session.execute(text("SELECT current_setting('app.current_tenant', true)"))
    value = result.scalar_one_or_none()
    if not value:
        raise ValueError("tenant context is required")
