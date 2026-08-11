"""Add least-privilege pre-tenant lookup functions."""

from alembic import op

revision = "0002_runtime_lookup_functions"
down_revision = "0001_secure_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_login_identity(login_email citext, login_slug text)
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
    op.execute(
        """
        CREATE OR REPLACE FUNCTION resolve_api_key(api_prefix text, api_digest text)
        RETURNS TABLE (
          key_id uuid,
          tenant_id uuid,
          scopes text[],
          ip_allowlist inet[]
        )
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        AS $fn$
          SELECT id, tenant_id, scopes, ip_allowlist
          FROM api_keys
          WHERE prefix = api_prefix
            AND key_hash = api_digest
            AND revoked_at IS NULL
          LIMIT 1
        $fn$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION resolve_api_key(text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_api_key(text, text) TO app_runtime")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS resolve_api_key(text, text)")
    op.execute("DROP FUNCTION IF EXISTS resolve_login_identity(citext, text)")
