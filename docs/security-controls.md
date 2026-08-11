# Security controls

The mappings below use NIST CSF 2.0 function/category labels as design mappings, not certification evidence. **We do not claim certification or compliance without an independent assessment.**

| ID | Control | NIST CSF 2.0 mapping | Component | Phase | Verification |
|---|---|---|---|---|---|
| SC-01 | Tenant isolation/RLS | PR.AA, PR.DS | DB/API | 1 | Security test |
| SC-02 | OIDC/SAML SSO | PR.AA | IdentityProvider | 6 | Integration test/review |
| SC-03 | Argon2id + TOTP MFA | PR.AA | Auth | 1 | Unit/security test |
| SC-04 | SCIM-ready provisioning | PR.AA | Users/IdP | 6 | Integration test |
| SC-05 | RBAC/ABAC and privileged workflows | PR.AA, GV.RR | Auth/cases | 1,6–7 | Security test |
| SC-06 | API key hashing, scopes, IP allow-list | PR.AA, PR.DS | API keys | 1 | Security test |
| SC-07 | TLS and encryption at rest | PR.DS | API/storage/DB | 1 | Configuration review |
| SC-08 | Optional customer-managed keys | PR.DS, GV.OV | Key boundary | 6 | Architecture review |
| SC-09 | Retention and customer-controlled deletion | PR.DS, GV.PO | Retention jobs | 6 | Integration test/review |
| SC-10 | Append-only hash-chained audit | PR.PS, DE.CM | Audit service | 1 | Tamper test |
| SC-11 | Evidence chain of custody | PR.DS, DE.AE | Evidence service | 1,3 | Integrity test |
| SC-12 | Backups, restore, DR | PR.DS, RC.RP | Operations | 1,6 | Restore exercise |
| SC-13 | HA and SLA tracking | PR.IR, RC.RP | Platform/status | 6 | Resilience test |
| SC-14 | Queue replay and DLQ | DE.CM, RC.RP | EventBus | 2 | Integration test |
| SC-15 | Connector health/retry/rate limits | DE.CM | Connectors | 2,5 | Integration test |
| SC-16 | Secure defaults/destructive actions off | PR.PS, GV.RR | Response | 7 | Security review |
| SC-17 | Human approval and rollback | PR.AA, RS.MI | Response | 7 | E2E test |
| SC-18 | Prompt-injection and output validation | PR.DS, DE.AE | AI service | 4 | Adversarial test |
| SC-19 | Asset/vulnerability/business risk context | ID.RA | Enrichment | 6 | Functional test |
| SC-20 | NIST/ATT&CK mappings | ID.RA, RS.AN | Detection/report | 3–6 | Review |
| SC-21 | Dependency/container scanning | ID.IM, PR.PS | CI/CD | 1 | Pipeline review |
| SC-22 | Penetration testing | ID.IM, GV.OV | Security program | 6+ | Independent test |
| SC-23 | Security disclosure process | GV.PO, ID.IM | Trust Centre | 6 | Process review |
| SC-24 | Customer support portal/status page | GV.RR, RC.CO | Operations | 6 | Operational review |
| SC-25 | Secrets management and redaction | PR.DS | Connectors/AI | 1,4 | Secret scan/test |
