from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


async def ensure_event_partitions(engine: AsyncEngine, months_ahead: int = 3, back_months: int = 2) -> None:
    if months_ahead < 0 or back_months < 0:
        raise ValueError("partition window must be non-negative")
    window_start = -back_months
    window_end = months_ahead
    async with engine.begin() as connection:
        await connection.execute(
            text(
                f"""
                DO $$
                DECLARE
                    month_start date;
                    month_end date;
                    partition_name text;
                    offset_month integer;
                BEGIN
                    FOR offset_month IN {window_start}..{window_end} LOOP
                        month_start := (
                            date_trunc('month', CURRENT_DATE)
                            + make_interval(months => offset_month)
                        )::date;
                        month_end := (month_start + interval '1 month')::date;
                        partition_name := 'events_' || to_char(month_start, 'YYYY_MM');
                        EXECUTE format(
                            'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
                            partition_name, month_start, month_end
                        );
                        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', partition_name);
                        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', partition_name);
                        EXECUTE format(
                            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO app_runtime',
                            partition_name
                        );
                        BEGIN
                            EXECUTE format(
                                'CREATE POLICY tenant_isolation ON %I USING '
                                '(tenant_id = current_setting(''app.current_tenant'', true)::uuid) '
                                'WITH CHECK '
                                '(tenant_id = current_setting(''app.current_tenant'', true)::uuid)',
                                partition_name
                            );
                        EXCEPTION WHEN duplicate_object THEN
                            NULL;
                        END;
                    END LOOP;
                END $$;
                """
            )
        )
