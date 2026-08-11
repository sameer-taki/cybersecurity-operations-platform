import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID, uuid4

from app.audit import append_audit
from app.auth import auth_sessions, authenticate, logout, rotate_refresh_token
from app.config import get_settings
from app.db import platform_session_factory
from app.deps import platform_admin_access, tenant_session
from app.event_contract import event_json_schema
from app.logging_redaction import SecretRedactionFilter
from app.rbac import Principal, attributes_match
from app.security import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    hash_password,
    hash_token,
    ip_allowed,
    new_api_key,
    new_totp_secret,
    recovery_codes,
    verify_totp,
)
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from jwt import PyJWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
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


class MfaConfirmationRequest(BaseModel):
    secret: str
    confirmation_code: str = Field(min_length=6, max_length=8)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.app_env.lower() not in {"development", "test"} and (
        settings.jwt_secret == "development-only-secret"
        or settings.totp_encryption_key == "0123456789abcdef0123456789abcdef"
    ):
        raise RuntimeError("refusing to start with development secrets outside a development environment")
    root_logger = logging.getLogger()
    root_logger.addFilter(SecretRedactionFilter([settings.jwt_secret, settings.totp_encryption_key]))
    yield


app = FastAPI(title="Fiji & Pacific Cyber Operations Platform", version="0.1.0", lifespan=lifespan)


@app.exception_handler(IntegrityError)
async def integrity_error_handler(_request: object, _exc: IntegrityError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": "request conflicts with existing data"},
    )


@app.post("/api/v1/auth/mfa/setup")
async def setup_mfa(
    session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> dict[str, object]:
    session, principal = session_and_principal
    secret = new_totp_secret()
    codes = recovery_codes()
    current = await session.execute(
        text("SELECT mfa_enabled FROM users WHERE id = :user FOR UPDATE"), {"user": principal.user_id}
    )
    if current.scalar_one_or_none() is None or current.scalar():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    await session.execute(
        text(
            "INSERT INTO totp_enrollments (user_id,tenant_id,encrypted_secret,recovery_code_hashes) "
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
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "auth.mfa_enrollment_started",
        "user",
        str(principal.user_id),
        {},
    )
    return {"secret": secret, "recovery_codes": codes, "confirmed": False}


@app.post("/api/v1/auth/mfa/confirm")
async def confirm_mfa(
    request: MfaConfirmationRequest,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> dict[str, object]:
    session, principal = session_and_principal
    if principal.user_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid MFA confirmation")
    pending = await session.execute(
        text("SELECT encrypted_secret, recovery_code_hashes FROM totp_enrollments WHERE user_id = :user FOR UPDATE"),
        {"user": principal.user_id},
    )
    pending_row = pending.mappings().first()
    if pending_row is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid MFA confirmation")
    pending_secret = decrypt_totp_secret(str(pending_row["encrypted_secret"]))
    if request.secret != pending_secret or not await asyncio.to_thread(
        verify_totp, pending_secret, request.confirmation_code
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid MFA confirmation")
    current = await session.execute(
        text("SELECT mfa_enabled FROM users WHERE id = :user FOR UPDATE"), {"user": principal.user_id}
    )
    if current.scalar_one_or_none() is None or current.scalar_one():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="MFA is already enabled")
    await session.execute(
        text(
            "INSERT INTO totp_secrets (user_id,tenant_id,encrypted_secret,recovery_code_hashes) "
            "VALUES (:user,:tenant,:secret,:codes)"
        ),
        {
            "user": principal.user_id,
            "tenant": principal.tenant_id,
            "secret": encrypt_totp_secret(request.secret),
            "codes": list(pending_row["recovery_code_hashes"] or []),
        },
    )
    await session.execute(text("DELETE FROM totp_enrollments WHERE user_id = :user"), {"user": principal.user_id})
    await session.execute(text("UPDATE users SET mfa_enabled = true WHERE id = :user"), {"user": principal.user_id})
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "auth.mfa_enrollment_confirmed",
        "user",
        str(principal.user_id),
        {},
    )
    return {"enabled": True}


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
    except (ValueError, KeyError, TypeError, PyJWTError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token") from None
    return {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
    }


@app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_route(request: TokenRequest) -> None:
    try:
        await logout(request.refresh_token)
    except (ValueError, KeyError, TypeError, PyJWTError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid refresh token") from None


async def require_tenant_admin(
    session_and_principal: tuple[AsyncSession, Principal] = Depends(tenant_session),
) -> tuple[AsyncSession, Principal]:
    session, principal = session_and_principal
    if "tenant:admin" not in principal.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
    assignments = await session.execute(
        text(
            "SELECT attributes FROM role_assignments ra "
            "JOIN roles r ON r.id = ra.role_id AND r.tenant_id = ra.tenant_id "
            "JOIN role_permissions rp ON rp.role_id = ra.role_id AND rp.tenant_id = ra.tenant_id "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE ra.user_id = :user AND ra.tenant_id = :tenant AND p.key = 'tenant:admin'"
        ),
        {"user": principal.user_id, "tenant": principal.tenant_id},
    )
    if not any(attributes_match(dict(row[0] or {}), principal.attributes) for row in assignments):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
    return session, principal


@app.post("/api/v1/platform/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(
    request: TenantCreateRequest,
    _access: Annotated[None, Depends(platform_admin_access)],
) -> dict[str, str]:
    async with platform_session_factory() as session:
        async with session.begin():
            tenant_id = uuid4()
            await session.execute(
                text("INSERT INTO tenants (id,name,slug) VALUES (:id,:name,:slug)"),
                {"id": tenant_id, "name": request.name, "slug": request.slug},
            )
            await session.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": str(tenant_id)},
            )
            await append_audit(session, tenant_id, None, "tenant.created", "tenant", str(tenant_id), {})
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
            "password": await asyncio.to_thread(hash_password, request.password),
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
    await session.execute(
        text("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = :id AND revoked_at IS NULL"),
        {"id": user_id},
    )
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


@app.post("/api/v1/tenant/api-keys/{key_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    session_and_principal: tuple[AsyncSession, Principal] = Depends(require_tenant_admin),
) -> None:
    session, principal = session_and_principal
    await session.execute(
        text("UPDATE api_keys SET revoked_at = now() WHERE id = :id AND tenant_id = :tenant"),
        {"id": key_id, "tenant": principal.tenant_id},
    )
    await append_audit(
        session,
        principal.tenant_id,
        principal.user_id,
        "tenant.api_key_revoked",
        "api_key",
        str(key_id),
        {},
    )


async def api_key_principal(
    api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    client_ip: Annotated[str | None, Header(alias="X-Forwarded-For")] = None,
    request: Request = None,  # type: ignore[assignment]
) -> Principal:
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    async with auth_sessions() as session:
        async with session.begin():
            result = await session.execute(
                text("SELECT * FROM resolve_api_key(:prefix, encode(digest(:key, 'sha256'), 'hex'))"),
                {"prefix": api_key[:12], "key": api_key},
            )
            row = result.mappings().first()
            if row is not None:
                await session.execute(
                    text("SELECT set_config('app.current_tenant', :tenant, true)"),
                    {"tenant": str(row["tenant_id"])},
                )
        peer_ip = request.client.host if request is not None and request.client is not None else client_ip
        settings = get_settings()
        if request is not None and peer_ip and settings.trusted_proxy and ip_allowed(peer_ip, [settings.trusted_proxy]):
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                peer_ip = forwarded.split(",")[-1].strip()
        if row is None or (
            row["ip_allowlist"] is not None and (not peer_ip or not ip_allowed(peer_ip, row["ip_allowlist"]))
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")
        return Principal(None, UUID(str(row["tenant_id"])), frozenset(row["scopes"]), {}, UUID(str(row["key_id"])))


def require_api_scope(scope: str) -> object:
    async def dependency(
        principal: Annotated[Principal, Depends(api_key_principal)],
    ) -> Principal:
        if scope not in principal.permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key scope required")
        return principal

    return dependency


@app.get("/api/v1/protected/events/summary")
async def protected_event_summary(
    principal: Annotated[Principal, Depends(require_api_scope("events:read"))],
) -> dict[str, str]:
    async with auth_sessions() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": str(principal.tenant_id)},
            )
            await append_audit(
                session,
                principal.tenant_id,
                None,
                "api_key.events_summary",
                "api_key",
                str(principal.key_id),
                {"api_key_id": str(principal.key_id)},
            )
    return {"status": "api-key-protected"}
