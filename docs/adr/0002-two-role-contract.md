# ADR 0002: DDL owner and runtime role

Status: accepted. Migrations run under a DDL/owner role. Runtime uses a separate `app_runtime` role that is non-superuser, cannot bypass RLS, and owns no tables. `platform_admin` handles control-plane tenant registry operations.
