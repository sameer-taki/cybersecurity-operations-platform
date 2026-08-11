---
name: testing-phase1-auth
description: How to bring up and adversarially test the multi-tenant auth/RBAC/audit backend of this repo over HTTP (login, MFA, refresh rotation, tenant isolation, API keys, audit chain) without a frontend.
---

# Testing the Phase 1 secure backend (HTTP/API only)

There is no frontend in Phase 1, so all testing is HTTP + out-of-band SQL assertions. Do not record a
screen video for this work; capture terminal output/text artifacts instead (rendering the assertion list
to a PNG with Pillow is a cheap way to get embeddable evidence for a PR comment).

## Bring up / verify the stack

```bash
./scripts/dev-up.sh                       # postgres 16, MinIO, Redis, migrate, seed, API on :8000
curl -s localhost:8000/health             # {"status":"ok"}
docker ps --format '{{.Names}}\t{{.Status}}'   # infra-api-1, infra-postgres-1, infra-minio-1, infra-redis-1
```

`dev-up.sh` copies `.env.example` to `.env` only if missing; the containers get their config from
`infra/docker-compose.yml` env blocks, so a missing `.env` on the host does not break the stack — but any
host-side script you write must set the vars itself (see below).

If a container image predates recent commits (e.g. a dependency bump), rebuild just the API:
`docker compose -f infra/docker-compose.yml up --build -d api` (this also re-runs `migrate`). Verify the
image really changed with `docker exec infra-api-1 sh -c 'uv pip list | grep -iE "^(pyjwt|cryptography|fastapi) "'`.

## Credentials and known-good values (development only)

- `admin1@example.com` (tenant `dev-tenant-1`) and `admin2@example.com` (tenant `dev-tenant-2`),
  password from `docs/setup.md`. Both are seeded with role `tenant_admin`
  (`tenant:admin`, `audit:read`, `events:read`, `incidents:write`).
- Dev JWT secret and TOTP key are in `infra/docker-compose.yml` (`JWT_SECRET`, `TOTP_ENCRYPTION_KEY`), so
  you can decode/forge tokens locally for adversarial probes.
- DB URLs (host): runtime `postgresql+asyncpg://app_api_login:app_runtime@localhost:5432/cyberops`,
  DDL owner `postgres:postgres`, registry `platform_admin_login:platform_admin`. Use the runtime role when
  asserting what the API can do, and the DDL owner only for tamper/negative controls.
- Quick SQL: `docker exec infra-postgres-1 psql -U postgres -d cyberops -At -c "<sql>"`.

## Devin Secrets Needed

None. Everything is local dev fixtures; no external secrets are required for this backend.

## Patterns that make the tests meaningful

- Keep the seeded admins usable: create throwaway fixtures via `POST /api/v1/tenant/users`
  (password must be >= 16 chars). A freshly invited user has **no roles**, which makes it the ideal
  non-admin principal for RBAC-denial tests, and the ideal victim for lockout/MFA tests.
- Lockout is 5 failures -> `locked_until = now() + 15 min`. Assert it in the DB
  (`users.failed_login_count`, `locked_until`), not just via status codes, because the whole point is that
  the counter commits on a request that ends in an exception. Reset with
  `UPDATE users SET failed_login_count=0, locked_until=NULL` between tests.
- MFA: `POST /api/v1/auth/mfa/setup` returns the base32 secret + 10 recovery codes once. Use `pyotp` for
  live codes, `pyotp.TOTP(secret).at(time.time()-120)` for a stale one (window is +/-1 step). Recovery codes
  go in the `totp_code` field and are removed from `totp_secrets.recovery_code_hashes` on use.
- Refresh families: `family_id` is a claim in the refresh JWT — decode it to target
  `refresh_tokens WHERE family_id = ...` when asserting family-wide revocation.
- Tenant isolation: the tenant comes only from the signed JWT/API-key row, never a header or body. Prove
  isolation by *effect* (target tenant's row unchanged, target's login/API key still works), because
  RLS-filtered writes legitimately return 204 while affecting zero rows.
- API keys: only the prefix + sha256 hash are stored; the IP allowlist is checked against the **first**
  `X-Forwarded-For` entry, so `X-Forwarded-For: <bad>, <allowed>` must still be refused.
- Audit chain: import `app.audit.verify_audit_chain` from `backend/`, set `app.current_tenant` on the
  connection first, and always add a negative control (tamper one `metadata` field inside a transaction you
  roll back) so a `True` result means something. Use one connection per statement when checking that
  `app_api_login` is denied UPDATE/DELETE/TRUNCATE on `audit_log`; reusing a connection that already began
  a transaction raises `InvalidRequestError` and can be mistaken for a permission denial (false pass).

## Known weak spot to check for regressions

`decode_token` (`backend/app/security.py`) raises `jwt.PyJWTError` subclasses, but callers in
`backend/app/deps.py` and `backend/app/auth.py` only catch `ValueError`/`KeyError`/`TypeError`. Any
invalid-signature, expired, wrong-issuer, `alg=none`, or malformed token therefore surfaces as
**HTTP 500 instead of 401** (including normal token expiry, and on `/auth/refresh` and `/auth/logout`).
Always include probes for: expired-but-correctly-signed token, wrong-secret signature, garbage bearer
string, and `"refresh_token": "abc.def.ghi"`. Response bodies stay generic (`Internal Server Error`), so
this leaks nothing to the client, but tracebacks land in the API log and the status code is wrong.
