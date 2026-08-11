# Backup and restore runbook

## Targets

The proposed targets are SaaS RPO ≤ 15 minutes/RTO ≤ 4 hours and dedicated RPO ≤ 15 minutes/RTO ≤ 2 hours. Customer-hosted targets are agreed per installation.

## Encrypted backup

1. Provision an encrypted destination controlled by the deployment owner; never put keys in the repository.
2. Run `pg_dump --format=custom --no-owner` over TLS or a protected local socket.
3. Encrypt the dump with the deployment KMS/key-management process.
4. Store the encrypted dump with restricted access and a SHA-256 checksum.
5. Record backup timestamp, schema revision, retention class, checksum, and operator in the audit system.
6. Back up MinIO raw objects with versioning/replication policy and verify object hashes against `raw_event_refs`.

## Restore rehearsal

For the Phase 1 rehearsal, the PostgreSQL 16 Docker container used to validate the migration was disposable. The DDL was applied with `alembic upgrade head`, verified with RLS/role queries, then removed; this proves schema recreation, not a production backup restore. The first operational rehearsal must:

1. Restore a recent encrypted dump into a clean PostgreSQL 16 database.
2. Restore raw objects into a clean S3-compatible bucket.
3. Run `alembic upgrade head` and verify the recorded revision.
4. Verify tenant RLS, forced partition RLS, role ownership, audit-chain integrity, and raw hashes.
5. Run the integration test suite and record elapsed restore time.
6. Document discrepancies and destroy the rehearsal environment securely.
