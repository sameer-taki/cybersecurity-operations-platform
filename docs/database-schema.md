# Database schema

`schema.sql` is a reviewable DDL sketch, not wired to Alembic. UUIDs are used for internal identifiers; externally exposed IDs should be opaque. Tenant-owned tables and every event partition carry `tenant_id` and use both `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`. Migrations run as a DDL/owner role; runtime uses a separate least-privilege `app_runtime` role with no `BYPASSRLS` and no table ownership. The control-plane service uses `platform_admin` for the tenant registry; `app_runtime` has no `SELECT` on `tenants`, which has an ID-matching policy as defence in depth. Request middleware must execute `SET LOCAL app.current_tenant = '<tenant uuid>'` in the same transaction before queries. Example:

```sql
CREATE POLICY tenant_isolation ON events
USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
```

Groups are identity/access, connectors/ingestion, event processing, detections/cases, risk context, AI/response, reporting/operations, and governance. Events are monthly range-partitioned by `observed_at`; JSONB `source`, `actor`, and `target` preserve flexible fields and use GIN indexes. `incident_events.event_tenant_id` exists only so the composite reference to partitioned `events` can carry the event tenant key; `CHECK (event_tenant_id = tenant_id)` prevents cross-tenant references. Raw objects remain immutable; `raw_event_refs` stores object URI/hash.

Audit is append-only with a per-tenant `prev_hash`/`entry_hash` chain. Evidence records reference artifact hashes and chain-of-custody transitions. Normalised events require non-null `raw_event_ref` and `raw_event_sha256`; every event therefore has retrievable raw bytes and a provenance hash. `retention_until` may be NULL only when a legal hold applies or no retention policy is configured; otherwise the retention worker must calculate it. Operational records use soft delete (`deleted_at`) where recovery/audit matters; raw/audit/evidence are never physically deleted except a policy-controlled retention process that records deletion. Retention workers process policies in batches, honour legal holds, and alert on failure.
