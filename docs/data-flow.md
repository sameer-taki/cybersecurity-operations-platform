# Data flows

Legend: `[TB-x]` is a trust boundary crossing; `=>` is synchronous and `~>` is asynchronous.

## A. Collection to storage

```text
[Customer network TB-1] Collector/connector
  => TLS ingest endpoint [TB-2] -> authenticate token + HMAC
  => immutable raw object store -> SHA-256 reference
  ~> EventBus stream -> parser worker -> schema validation/dedup
  ~> partitioned Postgres events [TB-3] -> search abstraction
```

- Classification: security telemetry, potentially personal and confidential.
- Readers: authorised tenant users; platform operators only through audited support access; parser has write/read of its queue scope.
- Retention: raw and normalised data follow `retention_policies`; raw may be shorter or equal to normalised retention.
- Protection: TLS 1.2+ in transit (verify exact deployment baseline); encrypted object/database volumes at rest; keys separated by deployment/tenant where supported.

## B. Detection to incident

```text
[Tenant data TB-3] events -> detection worker ~> alert
  -> dedup/correlation -> incident + incident_events
  -> analyst UI/API [TB-4] -> comments/tasks/notifications
```

- Classification: security findings and case data; incidents may contain restricted business context.
- Readers: tenant roles by permission and attribute; alert/detection workers receive only required tenant records.
- Retention: alerts/incidents follow case and evidence policy; audit is retained per legal/contractual policy.
- Protection: TLS for APIs/notifications; encrypted DB and exports; notification payloads minimise sensitive content.

## C. AI evidence bundle

```text
[Authorised analyst TB-4] request investigation
  ~> evidence-bundle builder [TB-5] -> tenant/RLS-filtered incident, events, assets, TI
  -> redact/separate untrusted log text -> LLMProvider [TB-6]
  <- schema-validated answer with evidence IDs
  -> persisted metadata/output -> human review -> incident timeline
```

- Classification: restricted incident evidence, possibly personal data and secrets.
- Readers: only the requesting authorised user and service scoped to the tenant; provider access is a decision pending data-residency approval.
- Retention: bundle is ephemeral by default; output and governance metadata follow investigation policy.
- Protection: TLS provider connection; encrypted transient storage and database; redact secrets; do not send data externally until approved.

## D. Approved response

```text
Analyst recommendation -> preview -> permission check
  -> human approver [TB-4] -> adapter [TB-7 external system]
  -> execute -> verify -> rollback if needed -> immutable audit
```

- Classification: high-impact operational command and credential metadata.
- Readers: authorised responders/approvers; adapter receives least-privilege action scope.
- Retention: action, approval, verification, and rollback records follow audit/case policy.
- Protection: mTLS/TLS to providers, encrypted connector secrets, never log secret values; destructive actions disabled by default.

## E. Reporting/export

```text
Tenant user -> report request [TB-4] ~> report service
  -> RLS-scoped query -> redaction/aggregation -> encrypted report object
  -> signed/expiring download or approved delivery
```

- Classification: report classification is selected at creation; executive reports may still be confidential.
- Readers: report permission plus tenant scope; exports are individually audited.
- Retention: report policy and legal hold apply; temporary objects expire.
- Protection: TLS download/delivery; encrypted object store; avoid secrets and unnecessary personal data.
