# First 30 days: Phase 1 secure foundation

Assumption: small team of two backend engineers, one platform engineer, and part-time product/security review.

| Week | Work item | Definition of done | Acceptance criteria |
|---|---|---|---|
| 1 | ADRs, dependency lock, Compose design, migration skeleton | Reviewed architecture choices; clean checkout starts planned services; no secrets | Local deployment; secrets absent |
| 1 | Tenant/user/role schema and RLS policies | Two tenants, roles, grants, and denied cross-tenant fixtures documented | Cross-tenant tests |
| 1–2 | Argon2id auth, TOTP, JWT/rotating refresh | Login, MFA enrollment, refresh reuse detection, logout tests | Secure foundation |
| 2 | Audit hash chain and admin event coverage | Create/update/delete/admin paths emit verifiable entries; audit writes cannot update/delete | Every admin action auditable |
| 2–3 | Event contract, raw object reference, retention metadata | JSON schema examples, hash calculation, object path rules, parser error model | Event schema/raw storage |
| 3 | Secret/config boundary and connector credential model | Secret references, redaction tests, no credentials in fixtures/logs | Secrets not in code |
| 3–4 | Backup/restore runbook and local operational checks | Encrypted backup procedure, restore rehearsal, RPO/RTO assumptions | Backup/restore documented |
| 4 | CI checks and security test suite | Lint/type/unit/integration/security jobs documented and runnable; clean checkout verified | CI; cross-tenant tests |

Definition of sprint done: design review sign-off, threat-model abuse cases converted into test cases, reproducible local setup, and a Phase 2 backlog with no production connector work hidden in Phase 1.
