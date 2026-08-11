"""Allow control-plane tenant creation to emit audit entries."""

from alembic import op

revision = "0003_platform_audit_grant"
down_revision = "0002_runtime_lookup_functions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT SELECT, INSERT ON audit_log TO platform_admin")


def downgrade() -> None:
    op.execute("REVOKE SELECT, INSERT ON audit_log FROM platform_admin")
