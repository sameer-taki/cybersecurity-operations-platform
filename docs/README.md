# Phase 0 design index

| Artifact | Purpose |
|---|---|
| [Architecture](architecture.md) | Context, services, boundaries, deployment, scaling, resilience |
| [Data flow](data-flow.md) | Trusted paths, classifications, access, retention, encryption |
| [Threat model](threat-model.md) | STRIDE, abuse cases, mitigations, ranked risks |
| [Security controls](security-controls.md) | NIST CSF 2.0 control matrix and verification |
| [Database schema](database-schema.md) / [DDL sketch](schema.sql) | Entities, tenancy, retention, reviewable SQL |
| [API resources](api-resources.md) | Versioned OpenAPI resource inventory |
| [Event schema](event-schema.md) | Normalisation and ingestion contract |
| [Detections](detections.md) | Initial detection catalogue and backlog |
| [AI investigation](ai-investigation.md) | Evidence bundle, JSON output, safeguards, evaluation |
| [Response actions](response-actions.md) | Human-approved action lifecycle |
| [Roadmap](roadmap.md) | Phases 1–8 and acceptance criteria |
| [30-day sprint](sprint-plan-30d.md) | Phase 1 small-team execution plan |
| [Open decisions](open-decisions.md) | Decisions requiring product/customer input |

No production runtime is included in Phase 0.

## Phase 1 additions

- [Setup](setup.md)
- [Backup and restore runbook](runbooks/backup-restore.md)
- [ADRs](adr/)
