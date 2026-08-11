# Roadmap

## Phases and acceptance criteria

### Phase 1 — Secure foundation

Multi-tenant database, authentication, roles/permissions, tenant administration, audit, event schema, raw storage, secrets management, Docker development environment, CI, unit/integration tests. **Acceptance:** cross-tenant tests pass; no secrets in code; every administrative action is auditable; clean-checkout local deployment works; backup/restore is documented.

### Phase 2 — Ingestion

JSON/CSV, HTTPS webhooks, Syslog TCP/TLS, parser SDK, queue processing, search, connector health, DLQ. **Acceptance:** malformed events do not crash; duplicates handled; failures replay; raw events retrievable; connector diagnostics work.

### Phase 3 — Detection and incidents

Rules, alerts, deduplication, correlation, cases, evidence timeline, assignment, notifications, technical/executive reports. **Acceptance:** synthetic attacks produce expected results; alerts group into incidents; analysts assign/escalate/comment/close; complete audit trail.

### Phase 4 — AI investigation

Bundles, prompts, structured output, confidence, references, ATT&CK/NIST mapping, injection controls, validation, fallback, governance. **Acceptance:** citations; unknowns; no cross-tenant access; logs cannot manipulate AI; failed calls preserve data; approve/reject/correct.

### Phase 5 — Integrations

Entra ID, Microsoft 365, WEF, Linux, firewall, EDR, cloud, ticketing, application/database connectors. Each has setup docs, test data, health, retry, integration tests.

### Phase 6 — Enterprise platform

SSO, SCIM, dedicated/customer-hosted deployment, retention, customer-managed keys, compliance, asset-risk, vulnerabilities, reporting, SLA, recovery, Trust Centre.

### Phase 7 — Controlled response

Approval, preview, mocks, live adapters, verification, rollback, audit, escalation. Destructive actions remain off by default.

### Phase 8 — Fiji pilot

90 days with three organisations; 3–5 sources each, ten detections, baselines, tabletop, monthly reports, false-positive and response metrics, feedback, integration issues, conversion review.

## Test strategy

Unit-test parsers, policy, RLS context, detection logic, schema validation, hash chains, and state transitions. Integration-test Postgres/RLS, object storage, Redis/DLQ/replay, connectors, notifications, and backups. Security-test tenant abuse, SSRF, secret leakage, auth/session replay, injection, IDOR, and privilege escalation. E2E-test synthetic attack scenarios from ingest to report and approved mock action. Run dependency/container scans and independent penetration testing before enterprise claims.
