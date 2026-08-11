# ADR 0001: shared-schema tenancy

Status: accepted. Shared-schema multi-tenancy uses `tenant_id` on tenant-owned rows, PostgreSQL RLS, and `SET LOCAL app.current_tenant` derived from the authenticated principal. Dedicated tenants use the same schema in a separate database.

Authentication uses a narrow `SECURITY DEFINER` function, `resolve_login_identity`,
to resolve email plus optional tenant slug before a tenant exists in request
context. The function has a fixed `public` search path, returns only the fields
needed to authenticate, and is executable only by `app_runtime`. After resolving
the tenant, the API opens a runtime-role transaction, sets `SET LOCAL
app.current_tenant`, and performs password, MFA, throttling, refresh-token, and
audit mutations through RLS. The DDL owner is never used for request traffic.
