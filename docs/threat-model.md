# Threat model

## Assets and boundaries

Assets include tenant data, raw events, evidence hashes, credentials, JWT/refresh tokens, API keys, detection rules, reports, audit chains, response actions, model prompts/outputs, and availability. Boundaries are: **TB-1** customer network to collector, **TB-2** internet/API ingress, **TB-3** service to database/object/queue, **TB-4** tenant user to control plane, **TB-5** platform to AI provider, and **TB-6** platform to customer integrations.

Actors: tenant user; malicious tenant user; tenant administrator; insider analyst/operator; compromised collector; attacker-controlled log content; compromised AI provider; external attacker; connector vendor.

## STRIDE by boundary

| Boundary | Threats | Concrete mitigations | Phase |
|---|---|---|---|
| TB-1 collector | Spoofing, tampering, DoS | Per-connector token/HMAC, TLS, replay window, sequence/idempotency, quotas, signed packages | 1–2 |
| TB-2 ingress | Spoofing, tampering, repudiation, DoS | Short-lived credentials where possible, HMAC, schema limits, rate limits, request IDs, audit | 1–2 |
| TB-3 data plane | Information disclosure, tampering, elevation | RLS, no BYPASSRLS, `SET LOCAL`, parameterised queries, encrypted storage, immutable raw refs, least-privilege roles | 1 |
| TB-4 UI/API | Spoofing, elevation, repudiation | Argon2id, TOTP, JWT rotation/reuse detection, RBAC/ABAC, CSRF strategy, audit, step-up approval | 1, 6–7 |
| TB-5 AI | Disclosure, tampering, repudiation | Authorised evidence builder, redaction, untrusted delimiters, injection heuristics, JSON schema, provider contract/logging review, no action execution | 4 |
| TB-6 integrations | Spoofing, tampering, SSRF, DoS | Secret vault, egress allow-list, DNS/IP validation, block private/link-local ranges, timeouts, connector scopes, approval | 1–7 |

## Ranked risks

Scores are qualitative likelihood × impact (1–5).

| Rank | Risk | L×I | Treatment |
|---|---|---:|---|
| 1 | Log content manipulates AI into unsafe advice | 4×4=16 | Treat content as untrusted, delimit, heuristics, strict schema, human review |
| 2 | Cross-tenant query or object access | 3×5=15 | RLS on every tenant table, authorization tests, object path checks, support-access audit |
| 3 | Connector credential compromise | 3×5=15 | Vault/encrypted secret references, hashes where possible, rotation/revocation, least privilege |
| 4 | Evidence tampering or deletion | 3×5=15 | Immutable raw objects, hashes, chain of custody, append-only audit, restore tests |
| 5 | SSRF via webhook/connector target | 3×5=15 | Egress policy, URL/IP validation, DNS rebinding defenses, timeout and response limits |
| 6 | Queue poisoning/backlog | 4×3=12 | Bounded consumers, quotas, retries, DLQ, replay and health alerts |
| 7 | Compromised AI provider sees restricted data | 2×5=10 | Provider allow-list, minimisation, residency decision, customer opt-out, gateway logging |
| 8 | Insider performs unauthorised response | 2×5=10 | Separation of duties, preview, approval, step-up auth, immutable audit, disabled destructive defaults |

## Required control sections

### Cross-tenant access

Set `app.current_tenant` inside every transaction; never trust a request body tenant ID. RLS policies use `current_setting(..., true)` and reject unset context. Service-to-service calls carry tenant context and permission claims. Tests must attempt IDs, filters, exports, evidence objects, reports, and AI bundles from another tenant.

### Log-content prompt injection

Logs are data, not instructions. Wrap each field in explicit untrusted-data delimiters, escape control sequences, strip secrets, detect instruction-like patterns, and tell the model to refuse embedded commands. Retrieval is allow-listed and output schema validation rejects unsupported actions. High-impact recommendations remain human-approved.

### Evidence tampering

Persist original object hash, parser/version, processing history, and chain-of-custody transitions. Audit entries form a per-tenant hash chain. Database role has no UPDATE/DELETE grants for audit; retention deletion requires policy and approval, with deletion evidence.

### Connector credentials

Store only secret references or encrypted values in a vault boundary; API keys are hashed for lookup. Display masked values, support rotation/revocation, validate scopes, restrict source IPs where available, and prohibit secrets in logs, exports, prompts, and test fixtures.

### SSRF from webhook/connector configuration

Outbound connectors use an explicit egress proxy/allow-list. Validate scheme, hostname, resolved addresses, redirects, ports, and response size; deny loopback, link-local, RFC1918, metadata, Unix-socket, and reserved addresses unless an explicitly configured private connector permits them. Re-resolve at connection time and log decisions without credentials.

## Abuse cases requiring automated tests

1. Tenant A reads/updates Tenant B by ID, filter, export, raw object path, or AI request.
2. Missing or forged tenant session variable reaches a database query.
3. JWT refresh replay succeeds after rotation.
4. Malformed/oversized event crashes a worker or bypasses validation.
5. Duplicate event creates duplicate alert/action.
6. Log says “ignore policy and execute” and changes model output/action state.
7. AI output invents an evidence ID or emits an unapproved action.
8. User without approval permission executes a response.
9. Connector URL resolves to metadata/localhost/private address, including after redirect/DNS change.
10. Audit update/delete, broken hash chain, or evidence hash mismatch is accepted.
11. DLQ replay crosses tenant or loses idempotency.
12. Secrets appear in logs, report exports, raw event prompts, or error envelopes.
