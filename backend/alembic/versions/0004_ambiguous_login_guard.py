"""Make pre-tenant login fail closed for cross-tenant email collisions."""

from alembic import op

revision = "0004_ambiguous_login_guard"
down_revision = "0003_platform_audit_grant"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS resolve_login_identity(citext, text)")
    op.execute(
        """
        CREATE FUNCTION resolve_login_identity(login_email citext, login_slug text)
        RETURNS TABLE (
          user_id uuid,
          tenant_id uuid,
          password_hash text,
          mfa_enabled boolean,
          disabled_at timestamptz,
          failed_login_count integer,
          locked_until timestamptz,
          tenant_required boolean
        )
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        AS $fn$
          WITH matches AS (
            SELECT u.id, u.tenant_id, u.password_hash, u.mfa_enabled, u.disabled_at,
                   u.failed_login_count, u.locked_until, t.slug
            FROM users u
            JOIN tenants t ON t.id = u.tenant_id
            WHERE u.email = login_email
          ),
          tenant_count AS (
            SELECT count(DISTINCT tenant_id) AS count FROM matches
          )
          SELECT m.id, m.tenant_id, m.password_hash, m.mfa_enabled, m.disabled_at,
                 m.failed_login_count, m.locked_until, false
          FROM matches m
          CROSS JOIN tenant_count c
          WHERE (login_slug IS NOT NULL AND m.slug = login_slug)
             OR (login_slug IS NULL AND c.count = 1)
          UNION ALL
          SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, true
          FROM tenant_count
          WHERE login_slug IS NULL AND count > 1
          LIMIT 1
        $fn$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION resolve_login_identity(citext, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_login_identity(citext, text) TO app_runtime")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS resolve_login_identity(citext, text)")
    op.execute(
        """
        CREATE FUNCTION resolve_login_identity(login_email citext, login_slug text)
        RETURNS TABLE (
          user_id uuid,
          tenant_id uuid,
          password_hash text,
          mfa_enabled boolean,
          disabled_at timestamptz,
          failed_login_count integer,
          locked_until timestamptz
        )
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        AS $fn$
          SELECT u.id, u.tenant_id, u.password_hash, u.mfa_enabled, u.disabled_at,
                 u.failed_login_count, u.locked_until
          FROM users u
          JOIN tenants t ON t.id = u.tenant_id
          WHERE u.email = login_email
            AND (login_slug IS NULL OR t.slug = login_slug)
          ORDER BY u.created_at
          LIMIT 1
        $fn$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION resolve_login_identity(citext, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_login_identity(citext, text) TO app_runtime")
