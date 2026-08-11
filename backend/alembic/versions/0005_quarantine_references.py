"""Separate quarantine state from legal hold and preserve immutable references."""

from alembic import op

revision = "0005_quarantine_references"
down_revision = "0004_ambiguous_login_guard"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE raw_event_refs ALTER COLUMN object_uri DROP NOT NULL")
    op.execute("ALTER TABLE raw_event_refs ADD COLUMN IF NOT EXISTS quarantine_uri text")
    op.execute("ALTER TABLE raw_event_refs ADD COLUMN IF NOT EXISTS quarantined_at timestamptz")
    op.execute(
        """
        ALTER TABLE raw_event_refs
        ADD CONSTRAINT raw_event_refs_storage_check
        CHECK (
          (object_uri IS NOT NULL AND quarantine_uri IS NULL AND quarantined_at IS NULL)
          OR (object_uri IS NULL AND quarantine_uri IS NOT NULL AND quarantined_at IS NOT NULL)
        )
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE raw_event_refs DROP CONSTRAINT IF EXISTS raw_event_refs_storage_check")
    op.execute("ALTER TABLE raw_event_refs DROP COLUMN IF EXISTS quarantined_at")
    op.execute("ALTER TABLE raw_event_refs DROP COLUMN IF EXISTS quarantine_uri")
    op.execute(
        "UPDATE raw_event_refs SET object_uri = 'object://raw/invalid/1970/01/01/legacy' WHERE object_uri IS NULL"
    )
    op.execute("ALTER TABLE raw_event_refs ALTER COLUMN object_uri SET NOT NULL")
