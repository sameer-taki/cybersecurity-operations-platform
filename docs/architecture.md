# Architecture

## Context

```text
Customer systems -> collectors/connectors -> encrypted ingestion -> EventBus
       ^                                                        |
       |                                                        v
 dashboards/reports <- cases/alerts <- detections <- normalisation/enrichment
                                      |
                                      v
                         authorised evidence -> AI -> human approval -> response
```

The platform is a shared-schema multi-tenant control plane. Every tenant-owned row carries `tenant_id`; PostgreSQL RLS is the final database boundary. The request context sets `SET LOCAL app.current_tenant`. Every tenant-owned table and partition uses both `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`.

Migrations run as a separate DDL/owner role. `app_runtime` and `platform_admin` are `NOLOGIN` group roles; deployment creates per-service `LOGIN` roles and grants membership. Each connecting login must be `NOSUPERUSER`, have no `BYPASSRLS`, and own no application objects. The control-plane service uses `platform_admin` for tenant-registry operations; tenant-plane runtime access has no `SELECT` privilege on `tenants`.

## Core services and boundaries

| Service | Responsibility | Synchronous boundary | Asynchronous boundary |
|---|---|---|---|
| API service | Authenticated CRUD for tenants, connectors, cases, reports | REST to browser/clients | Publishes jobs/events |
| Web application | Customer and analyst UI | REST/query cache | Subscribes through API |
| Ingestion service | Authenticates and accepts webhook/import/syslog input | Ingest acknowledgement | Writes raw object and queue message |
| Collector service | Customer-side collection and batching | Connector protocol | Sends signed batches |
| Queue/EventBus | Durable work streams, retry, DLQ, replay | Publish/claim | Redis Streams phase 1–3; NATS/Kafka later |
| Parser workers | Validate, parse, normalise, deduplicate | — | Consumes ingestion stream; emits normalised events |
| Detection engine | Rules, thresholds, correlation | Rule administration API | Consumes events; emits alerts |
| Enrichment service | Asset, identity, vulnerability, TI context | Lookup API | Refresh and enrichment jobs |
| AI investigation service | Evidence bundles, LLM calls, validated output | Investigation API | Long-running retrieval/model jobs |
| Case-management service | Incidents, evidence, tasks, comments, approvals | Case API | Notifications and audit events |
| Report service | Technical, executive, compliance, exports | Report request/status API | Generates artefacts asynchronously |
| Audit service | Hash-chained access/activity records | Append audit entry | Replication/export of audit records |
| Notification service | Email, SMS, webhook, ticketing notifications | Configuration API | Delivery, retry, dead-letter |

Raw event objects live in S3-compatible storage at `object://raw/<tenant_id>/<YYYY>/<MM>/<DD>/<event_id>`; the tenant segment is derived server-side from authenticated context, never accepted from event input, and reads validate it against the session tenant. Postgres stores the SHA-256 and reference. Search uses an abstraction over partitioned Postgres tables so OpenSearch can be introduced without changing APIs.

## Deployment models

| Model | Isolation and operations | Differences |
|---|---|---|
| SaaS | Shared application/database, strict RLS, central updates | Standard connectors, subscription service, provider-managed backups |
| Dedicated tenant | Separate database/environment using the same migrations | Customer-specific retention/encryption, private connectivity, higher SLA |
| Customer-hosted | Full stack in customer infrastructure via Compose/Helm | Customer controls storage/network/keys; offline or restricted support paths |

## Technology rationale

FastAPI and Pydantic provide typed HTTP contracts; SQLAlchemy/Alembic provide explicit async persistence and migration control. PostgreSQL 16 is the initial system of record because partitioning, JSONB, indexes, and RLS cover the initial scale while avoiding an early search dependency. MinIO models S3-compatible raw storage in development. Redis Streams is intentionally behind `EventBus`, allowing later NATS/Kafka adoption when throughput or multi-region needs justify it. React/Vite/TanStack Query keep the planned UI typed and cache-aware.

## Scaling and failure modes

- Partition `events` monthly by `observed_at`; the partition-management job must create the current month, N months ahead, and a small back-window, then apply grants for direct maintenance access plus `ENABLE` + `FORCE ROW LEVEL SECURITY` and the parent policy to every partition. Do not create a DEFAULT partition: ingestion clamps/quarantines out-of-range or clock-skewed observations to a parse-failure/quarantine path while retaining original bytes.
- Apply bounded queue consumers and per-tenant quotas to create backpressure rather than dropping events.
- Retry transient work with exponential backoff; poison messages go to a tenant-scoped DLQ with reason and original payload reference.
- Replay is an explicit, audited operation with idempotency keys and parser-version selection.
- Run API/workers stateless behind a load balancer; use PostgreSQL HA and Redis replication appropriate to the deployment model.
- Raw objects are immutable/versioned where supported; database backups are encrypted and restore-tested.
- Proposed targets: SaaS RPO ≤ 15 minutes, RTO ≤ 4 hours; dedicated RPO ≤ 15 minutes, RTO ≤ 2 hours; customer-hosted targets are agreed per installation.
- Retention deletion is policy-driven, two-person approval for destructive administrative operations, and produces audit evidence.
- Provider outage: accept/queue within capacity, expose connector health, retry, and preserve raw input; LLM outage never blocks incident operations.
- Clock skew is retained as source metadata; observed time is validated and ingestion time remains authoritative for processing order.
