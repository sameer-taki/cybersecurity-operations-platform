# Database schema

`schema.sql` is a reviewable DDL sketch, not wired to Alembic. UUIDs are used for internal identifiers; externally exposed IDs should be opaque. Tenant-owned tables carry `tenant_id` and enable RLS. Request middleware must execute `SET LOCAL app.current_tenant = '<tenant uuid>'` in the same transaction before queries. Example:

```sql
CREATE POLICY tenant_isolation ON events
USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);
```

Groups are identity/access, connectors/ingestion, event processing, detections/cases, risk context, AI/response, reporting/operations, and governance. Events are monthly range-partitioned by `observed_at`; JSONB `source`, `actor`, and `target` preserve flexible fields and use GIN indexes. Raw objects remain immutable; `raw_event_refs` stores object URI/hash.

Audit is append-only with a per-tenant `prev_hash`/`entry_hash` chain. Evidence records reference artifact hashes and chain-of-custody transitions. Operational records use soft delete (`deleted_at`) where recovery/audit matters; raw/audit/evidence are never physically deleted except a policy-controlled retention process that records deletion. Retention workers process policies in batches, honour legal holds, and alert on failure.
