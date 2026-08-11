# Fiji & Pacific Cyber Operations Platform

Phase 0 design for an enterprise, multi-tenant cyber monitoring and incident-response platform for Fiji and the Pacific. The platform collects security telemetry, normalises and detects threats, preserves evidence, supports human-reviewed AI investigation, reports risk, and enables approved response actions.

## Capability pillars

1. **Visibility** — connectors, collectors, raw and normalised event search.
2. **Detection** — explainable SIEM-style rules and correlation.
3. **Investigation** — incidents, evidence, enrichment, and AI assistance.
4. **Response** — preview, approval, execution, verification, and rollback.
5. **Risk context** — assets, identities, vulnerabilities, and business services.
6. **Reporting** — technical, executive, compliance, and operational reports.
7. **Governance** — tenant isolation, auditability, retention, resilience, and controls.

## Planned technology stack

- Backend: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2 async, Alembic.
- Dependency management: **uv** for fast, reproducible Python environments and lockfile-based development.
- Frontend: React 18, TypeScript, Vite, TanStack Query, Tailwind.
- Data: PostgreSQL 16 (partitioned events, JSONB/GIN), S3-compatible raw storage.
- Queue: Redis Streams behind an `EventBus`; NATS/Kafka remain swap-in options.
- Deployment: Docker Compose for development; Kubernetes/Helm-ready production.
- Likely hosted pilot: Railway, with Cloudflare DNS/WAF; both are tentative pending the decisions in [open decisions](docs/open-decisions.md).

## Planned repository layout

```text
backend/                 # planned FastAPI services and workers
frontend/                # planned React application
infra/                   # planned Compose, Helm, and operational configuration
tests/                   # planned unit, integration, security, and end-to-end tests
docs/                    # Phase 0 design artifacts (current deliverable)
```

## Navigate the design

Start with the [Phase 0 index](docs/README.md), then read [architecture](docs/architecture.md), [data flows](docs/data-flow.md), [threat model](docs/threat-model.md), and [roadmap](docs/roadmap.md). The [schema](docs/database-schema.md), [API resource list](docs/api-resources.md), and [event contract](docs/event-schema.md) define implementation boundaries.

## Status

**Phase 0: design; no runtime code yet.**
