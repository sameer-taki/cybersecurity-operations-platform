"""Apply tenant controls only to actual events partitions."""

from alembic import op

revision = "0006_partition_policy_scope"
down_revision = "0005_quarantine_references"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE partition_name text;
        BEGIN
          FOR partition_name IN
            SELECT child.relname
            FROM pg_inherits i
            JOIN pg_class parent ON parent.oid = i.inhparent
            JOIN pg_class child ON child.oid = i.inhrelid
            JOIN pg_namespace schema_info ON schema_info.oid = child.relnamespace
            WHERE parent.relname = 'events' AND schema_info.nspname = current_schema()
          LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', partition_name);
            BEGIN
              EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.current_tenant'', true)::uuid) WITH CHECK (tenant_id = current_setting(''app.current_tenant'', true)::uuid)',
                partition_name
              );
            EXCEPTION WHEN duplicate_object THEN NULL;
            END;
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_runtime', partition_name);
          END LOOP;
        END $$;
        """
    )


def downgrade() -> None:
    pass
