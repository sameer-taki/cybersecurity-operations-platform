# ADR 0002: DDL owner and runtime role

Status: accepted. Migrations run under a DDL/owner role. Runtime uses separate
service LOGIN identities: `app_api_login` is granted membership in the
non-login `app_runtime` group, and `platform_admin_login` is granted membership
in the non-login `platform_admin` group. The API tenant plane uses the former;
control-plane tenant-registry operations use the latter. Neither runtime
identity owns application objects, is superuser, or can bypass RLS. Authentication
uses the narrowly scoped login-identity function documented in ADR 0001 rather
than the DDL owner.
