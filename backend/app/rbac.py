from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Principal:
    user_id: UUID | None
    tenant_id: UUID
    permissions: frozenset[str]
    attributes: dict[str, object]
    key_id: UUID | None = None


def requires(permission: str) -> object:
    async def dependency(principal: Principal) -> Principal:
        if permission not in principal.permissions:
            raise PermissionError("permission denied")
        return principal

    return dependency


def attributes_match(attributes: dict[str, object], context: dict[str, object]) -> bool:
    return all(context.get(key) == expected for key, expected in attributes.items())


async def permission_keys(
    session: AsyncSession,
    user_id: UUID,
    context: dict[str, object] | None = None,
) -> frozenset[str]:
    attribute_context = context or {}
    rows = await session.execute(
        text(
            "SELECT DISTINCT p.key, ra.attributes FROM permissions p "
            "JOIN role_permissions rp ON rp.permission_id = p.id "
            "JOIN role_assignments ra ON ra.role_id = rp.role_id AND ra.tenant_id = rp.tenant_id "
            "WHERE ra.user_id = :user_id"
        ),
        {"user_id": user_id},
    )
    return frozenset(str(row[0]) for row in rows if attributes_match(dict(row[1] or {}), attribute_context))
