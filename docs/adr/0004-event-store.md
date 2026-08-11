# ADR 0004: partitioned PostgreSQL event store

Status: accepted. Phase 1 stores the normalised contract in monthly partitioned PostgreSQL tables with JSONB/GIN and raw bytes in S3-compatible storage. Search remains behind an abstraction for later OpenSearch adoption.
