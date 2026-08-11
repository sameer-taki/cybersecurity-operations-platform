from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID, uuid4

from app.audit import append_audit
from app.auth import auth_sessions, authenticate, logout, rotate_refresh_token
from app.db import platform_session_factory
from app.deps import tenant_session
from app.event_contract import event_json_schema
from app.rbac import Principal
from app.security import (
    encrypt_totp_secret,
    hash_password,
    hash_token,
    ip_allowed,
    new_api_key,
    new_totp_secret,
    recovery_codes,
)
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None
    tenant_slug: str | None = None


class TokenRequest(BaseModel):
    refresh_token: str


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")


class UserInviteRequest(BaseModel):
    email: EmailStr
    display_name: str
    password: str = Field(min_length=16)


class RoleAssignmentRequest(BaseModel):
    user_id: UUID
    role_id: UUID


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    scopes: list[str] = Field(min_length=1)
    ip_allowlist: list[str] | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield


app = FastAPI(title="Fiji & Pacific Cyber Operations Platform", version="0.1.0", lifespan=lifespan)


@app.post("/api/v1/auth/mfa/setup")
async def setup_mfa(
    session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> dict[str, object]:
    session, principal = session_and_principal
    secret = new_totp_secret()
    codes = recovery_codes()
    await session.execute(
        text(
            "INSERT INTO totp_secrets (user_id,tenant_id,encrypted_secret,recovery_code_hashes) "
            "VALUES (:user,:tenant,:secret,:codes) "
            "ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, "
            "recovery_code_hashes = EXCLUDED.recovery_code_hashes"
        ),
        {
            "user": principal.user_id,
            "tenant": principal.tenant_id,
            "secret": encrypt_totp_secret(secret),
            "codes": [hash_token(code) for code in codes],
        },
    )
    await session.execute(text("UPDATE users SET mfa_enabled = true WHERE id = :user"), {"user": principal.user_id})
    await append_audit(
        session, principal.tenant_id, principal.user_id, "auth.mfa_enabled", "user", str(principal.user_id), {}
    )
    return {"secret": secret, "recovery_codes": codes}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/events/schema")
async def event_schema() -> dict[str, object]:
    return event_json_schema()


@app.get("/api/v1/tenant-context")
async def tenant_context(
    _session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> dict[str, str]:
    return {"status": "tenant-scoped"}


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest) -> dict[str, str]:
    try:
        tokens = await authenticate(request.email, request.password, request.totp_code, request.tenant_slug)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from None
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
    }


@app.post("/api/v1/auth/refresh")
async def refresh(request: TokenRequest) -> dict[str, str]:
    try:
        tokens = await rotate_refresh_token(request.refresh_token)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from None
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
    }


@app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_route(request: TokenRequest) -> None:
    try:
        await logout(request.refresh_token)
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token") from exc


async def require_tenant_admin(
    session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> tuple[AsyncSession, Principal]:
    session, principal = session_and_principal
    if "tenant:admin" not in principal.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
    return session, principal


@app.post("/api/v1/platform/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(request: TenantCreateRequest) -> dict[str, str]:
    async with platform_session_factory() as session:
        async with session.begin():
            tenant_id = uuid4()
            await session.execute(
                text("INSERT INTO tenants (id,name,slug) VALUES (:id,:name,:slug)"),
                {"id": tenant_id, "name": request.name, "slug": request.slug},
            )
    return {"id": str(tenant_id), "slug": request.slug}


@app.post("/api/v1/tenant/users", status_code=status.HTTP_201_CREATED)
async def invite_user(
    request: UserInviteRequest,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(require_tenant_admin),
) -> dict[str, str]:
    session, principal = session_and_principal
    user_id = uuid4()
    await session.execute(
        text(
            "INSERT INTO users (id,tenant_id,email,display_name,password_hash) "
            "VALUES (:id,:tenant,:email,:name,:password)"
        ),
        {
            "id": user_id,
            "tenant": principal.tenant_id,
            "email": request.email,
            "name": request.display_name,
            "password": hash_password(request.password),
        },
    )
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "tenant.user_invited",
        "user",
        str(user_id),
        {"email": str(request.email)},
    )
    return {"id": str(user_id), "email": str(request.email)}


@app.post("/api/v1/tenant/users/{user_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_user(
    user_id: UUID,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(require_tenant_admin),
) -> None:
    session, _principal = session_and_principal
    await session.execute(text("UPDATE users SET disabled_at = now() WHERE id = :id"), {"id": user_id})
    await append_audit(
        session, _principal.tenant_id, _principal.user_id, "tenant.user_disabled", "user", str(user_id), {}
    )


@app.post("/api/v1/tenant/role-assignments", status_code=status.HTTP_204_NO_CONTENT)
async def assign_role(
    request: RoleAssignmentRequest,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(require_tenant_admin),
) -> None:
    session, principal = session_and_principal
    await session.execute(
        text("INSERT INTO role_assignments (tenant_id,user_id,role_id) VALUES (:tenant,:user,:role)"),
        {"tenant": principal.tenant_id, "user": request.user_id, "role": request.role_id},
    )
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "tenant.role_assigned",
        "role_assignment",
        str(request.role_id),
        {"user_id": str(request.user_id)},
    )


@app.post("/api/v1/tenant/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: ApiKeyCreateRequest,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(require_tenant_admin),
) -> dict[str, str | list[str]]:
    session, principal = session_and_principal
    prefix, secret, digest = new_api_key()
    key_id = uuid4()
    await session.execute(
        text(
            "INSERT INTO api_keys "
            "(id,tenant_id,name,prefix,key_hash,scopes,ip_allowlist) "
            "VALUES (:id,:tenant,:name,:prefix,:hash,:scopes,:ips)"
        ),
        {
            "id": key_id,
            "tenant": principal.tenant_id,
            "name": request.name,
            "prefix": prefix,
            "hash": digest,
            "scopes": request.scopes,
            "ips": request.ip_allowlist,
        },
    )
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "tenant.api_key_created",
        "api_key",
        str(key_id),
        {"scopes": request.scopes},
    )
    return {"id": str(key_id), "secret": secret, "scopes": request.scopes}


async def api_key_principal(
    api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    client_ip: Annotated[str | None, Header(alias="X-Forwarded-For")] = None,
) -> Principal:
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    async with auth_sessions() as session:
        result = await session.execute(
            text(
                "SELECT id, tenant_id, scopes, ip_allowlist FROM api_keys "
                "WHERE prefix = :prefix AND key_hash = encode(digest(:key, 'sha256'), 'hex') "
                "AND revoked_at IS NULL"
            ),
            {"prefix": api_key[:12], "key": api_key},
        )
        row = result.mappings().first()
        if row is None or (client_ip and not ip_allowed(client_ip.split(",")[0].strip(), row["ip_allowlist"])):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")
        return Principal(UUID(str(row["id"])), UUID(str(row["tenant_id"])), frozenset(row["scopes"]), {})
