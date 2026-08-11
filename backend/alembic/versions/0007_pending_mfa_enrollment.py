"""Keep MFA enrollment secrets pending until proof of possession."""

from alembic import op

revision = "0007_pending_mfa_enrollment"
down_revision = "0006_partition_policy_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS totp_enrollments (
          user_id uuid PRIMARY KEY,
          tenant_id uuid NOT NULL REFERENCES tenants(id),
          encrypted_secret text NOT NULL,
          recovery_code_hashes text[] NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
        )
        """
    )
    op.execute("ALTER TABLE totp_enrollments ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE totp_enrollments FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON totp_enrollments
        USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
        WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
        """
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON totp_enrollments TO app_runtime")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS totp_enrollments")
