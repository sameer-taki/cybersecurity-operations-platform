from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from app.db import session_factory
from app.rbac import Principal
from app.security import decode_token
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def authenticated_principal(
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    try:
        payload = decode_token(authorization.removeprefix("Bearer "), "access")
        user_id = UUID(str(payload["sub"]))
        tenant_id = UUID(str(payload["tenant_id"]))
    except (ValueError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token") from None
    permissions_value = payload.get("permissions", [])
    if not isinstance(permissions_value, list) or not all(isinstance(item, str) for item in permissions_value):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token claims")
    return Principal(user_id, tenant_id, frozenset(permissions_value), {})


async def tenant_session(
    principal: Annotated[Principal, Depends(authenticated_principal)],
) -> AsyncIterator[tuple[AsyncSession, Principal]]:
    async with session_factory() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": str(principal.tenant_id)},
            )
            yield session, principal
