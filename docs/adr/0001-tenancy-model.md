# ADR 0001: shared-schema tenancy

Status: accepted. Shared-schema multi-tenancy uses `tenant_id` on tenant-owned rows, PostgreSQL RLS, and `SET LOCAL app.current_tenant` derived from the authenticated principal. Dedicated tenants use the same schema in a separate database.
