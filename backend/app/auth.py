from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.audit import append_audit
from app.db import session_factory
from app.security import (
    DUMMY_PASSWORD_HASH,
    decode_token,
    decrypt_totp_secret,
    hash_token,
    issue_access_token,
    issue_refresh_token,
    verify_password,
    verify_totp,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


auth_sessions = session_factory


async def _set_tenant(session: AsyncSession, tenant_id: UUID) -> None:
    await session.execute(
        text("SELECT set_config('app.current_tenant', :tenant, true)"),
        {"tenant": str(tenant_id)},
    )


async def authenticate(
    email: str,
    password: str,
    totp_code: str | None,
    tenant_slug: str | None,
) -> TokenPair:
    async with auth_sessions() as session:
        async with session.begin():
            row = await session.execute(
                text("SELECT * FROM resolve_login_identity(CAST(:email AS citext), CAST(:slug AS text))"),
                {"email": email, "slug": tenant_slug},
            )
            user = row.mappings().first()
            now = datetime.now(UTC)
            if user is None:
                verify_password(password, DUMMY_PASSWORD_HASH)
                raise ValueError("invalid credentials")
            if bool(user["tenant_required"]):
                verify_password(password, DUMMY_PASSWORD_HASH)
                raise ValueError("tenant required")
            user_id = UUID(str(user["user_id"]))
            tenant_id = UUID(str(user["tenant_id"]))
            await _set_tenant(session, tenant_id)
            locked = await session.execute(
                text(
                    "SELECT id, tenant_id, password_hash, mfa_enabled, disabled_at, "
                    "failed_login_count, locked_until FROM users WHERE id = :user FOR UPDATE"
                ),
                {"user": user_id},
            )
            user = locked.mappings().first()
            if user is None:
                raise ValueError("invalid credentials")
            locked_until = user["locked_until"]
            if user["disabled_at"] is not None or (locked_until is not None and locked_until > now):
                await append_audit(session, tenant_id, user_id, "auth.login_denied", "user", str(user_id), {})
                raise ValueError("account unavailable")
            valid = user["password_hash"] is not None and verify_password(password, str(user["password_hash"]))
            recovery_hashes: list[str] = []
            if user["mfa_enabled"] and valid:
                secret_row = await session.execute(
                    text("SELECT encrypted_secret, recovery_code_hashes FROM totp_secrets WHERE user_id = :user"),
                    {"user": user_id},
                )
                secret = secret_row.mappings().first()
                if secret is None or totp_code is None:
                    valid = False
                else:
                    decrypted = decrypt_totp_secret(str(secret["encrypted_secret"]))
                    valid = verify_totp(decrypted, totp_code)
                    recovery_hashes = [str(item) for item in (secret["recovery_code_hashes"] or [])]
                    recovery_hash = hash_token(totp_code)
                    if not valid and recovery_hash in recovery_hashes:
                        valid = True
                        recovery_hashes.remove(recovery_hash)
                        await session.execute(
                            text("UPDATE totp_secrets SET recovery_code_hashes = :codes WHERE user_id = :user"),
                            {"codes": recovery_hashes, "user": user_id},
                        )
            if not valid:
                await session.execute(
                    text(
                        "UPDATE users SET failed_login_count = failed_login_count + 1, "
                        "locked_until = CASE WHEN failed_login_count + 1 >= 5 "
                        "THEN :lock_until ELSE locked_until END WHERE id = :user"
                    ),
                    {"lock_until": now + timedelta(minutes=15), "user": user_id},
                )
                await append_audit(session, tenant_id, user_id, "auth.login_failed", "user", str(user_id), {})
                raise ValueError("invalid credentials")
            await session.execute(
                text("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = :user"),
                {"user": user_id},
            )
            permissions = await session.execute(
                text(
                    "SELECT DISTINCT p.key FROM permissions p "
                    "JOIN role_permissions rp ON rp.permission_id = p.id "
                    "JOIN role_assignments ra ON ra.role_id = rp.role_id AND ra.tenant_id = rp.tenant_id "
                    "WHERE ra.user_id = :user AND ra.tenant_id = :tenant"
                ),
                {"user": user_id, "tenant": tenant_id},
            )
            permission_keys = [str(item[0]) for item in permissions]
            family_id = uuid4()
            refresh, expires_at = issue_refresh_token(user_id, tenant_id, family_id)
            await session.execute(
                text(
                    "INSERT INTO refresh_tokens "
                    "(tenant_id,user_id,family_id,token_hash,expires_at) "
                    "VALUES (:tenant,:user,:family,:token_hash,:expires)"
                ),
                {
                    "tenant": tenant_id,
                    "user": user_id,
                    "family": family_id,
                    "token_hash": hash_token(refresh),
                    "expires": expires_at,
                },
            )
            await append_audit(session, tenant_id, user_id, "auth.login_succeeded", "user", str(user_id), {})
            return TokenPair(issue_access_token(user_id, tenant_id, permission_keys), refresh)


async def rotate_refresh_token(token: str) -> TokenPair:
    claims = decode_token(token, "refresh")
    user_id = UUID(str(claims["sub"]))
    tenant_id = UUID(str(claims["tenant_id"]))
    family_id = UUID(str(claims["family_id"]))
    async with auth_sessions() as session:
        reuse_detected = False
        pair: TokenPair | None = None
        async with session.begin():
            await _set_tenant(session, tenant_id)
            result = await session.execute(
                text(
                    "SELECT id, used_at, revoked_at, expires_at FROM refresh_tokens "
                    "WHERE token_hash = :token AND family_id = :family FOR UPDATE"
                ),
                {"token": hash_token(token), "family": family_id},
            )
            stored = result.mappings().first()
            now = datetime.now(UTC)
            if (
                stored is None
                or stored["used_at"] is not None
                or stored["revoked_at"] is not None
                or stored["expires_at"] <= now
            ):
                await session.execute(
                    text("UPDATE refresh_tokens SET revoked_at = :now WHERE family_id = :family"),
                    {"now": now, "family": family_id},
                )
                await append_audit(
                    session, tenant_id, user_id, "auth.refresh_reuse", "token_family", str(family_id), {}
                )
                reuse_detected = True
            else:
                await session.execute(
                    text("UPDATE refresh_tokens SET used_at = :now WHERE id = :id"),
                    {"now": now, "id": stored["id"]},
                )
                permission_rows = await session.execute(
                    text(
                        "SELECT DISTINCT p.key FROM permissions p "
                        "JOIN role_permissions rp ON rp.permission_id = p.id "
                        "JOIN role_assignments ra ON ra.role_id = rp.role_id AND ra.tenant_id = rp.tenant_id "
                        "WHERE ra.user_id = :user AND ra.tenant_id = :tenant"
                    ),
                    {"user": user_id, "tenant": tenant_id},
                )
                permissions = [str(item[0]) for item in permission_rows]
                new_refresh, expires_at = issue_refresh_token(user_id, tenant_id, family_id)
                await session.execute(
                    text(
                        "INSERT INTO refresh_tokens "
                        "(tenant_id,user_id,family_id,token_hash,expires_at) "
                        "VALUES (:tenant,:user,:family,:token_hash,:expires)"
                    ),
                    {
                        "tenant": tenant_id,
                        "user": user_id,
                        "family": family_id,
                        "token_hash": hash_token(new_refresh),
                        "expires": expires_at,
                    },
                )
                await append_audit(
                    session, tenant_id, user_id, "auth.refresh_rotated", "token_family", str(family_id), {}
                )
                pair = TokenPair(issue_access_token(user_id, tenant_id, permissions), new_refresh)
        if reuse_detected:
            raise ValueError("refresh token reuse detected")
        if pair is None:
            raise RuntimeError("refresh token transaction produced no result")
        return pair


async def logout(token: str) -> None:
    claims = decode_token(token, "refresh")
    family_id = UUID(str(claims["family_id"]))
    user_id = UUID(str(claims["sub"]))
    tenant_id = UUID(str(claims["tenant_id"]))
    async with auth_sessions() as session:
        async with session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                text("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = :family"),
                {"family": family_id},
            )
            await append_audit(session, tenant_id, user_id, "auth.logout", "token_family", str(family_id), {})
