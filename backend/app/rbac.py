from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    permissions: frozenset[str]
    attributes: dict[str, object]


def requires(permission: str) -> object:
    async def dependency(principal: Principal) -> Principal:
        if permission not in principal.permissions:
            raise PermissionError("permission denied")
        return principal

    return dependency


async def permission_keys(session: AsyncSession, user_id: UUID) -> frozenset[str]:
    rows = await session.execute(
        text(
            "SELECT DISTINCT p.key FROM permissions p "
            "JOIN role_permissions rp ON rp.permission_id = p.id "
            "JOIN role_assignments ra ON ra.role_id = rp.role_id AND ra.tenant_id = rp.tenant_id "
            "WHERE ra.user_id = :user_id"
        ),
        {"user_id": user_id},
    )
    return frozenset(row[0] for row in rows)
