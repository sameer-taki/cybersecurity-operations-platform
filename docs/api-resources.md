# API resource list

Base path is `/api/v1`. JSON errors use `{ "error": { "code": "...", "message": "...", "request_id": "...", "details": {} } }`; details never contain secrets. Cursor pagination uses opaque `cursor` and bounded `limit`; filters are explicit query parameters, with tenant scope always derived from auth.

| Resource | Paths and methods | Required permission | Idempotency |
|---|---|---|---|
| Auth/session | `/auth/login`, `/auth/refresh`, `/auth/logout`; POST | unauthenticated/login policy | refresh rotation; replay rejected |
| Tenants/users/roles | `/tenants`, `/users`, `/roles`, `/permissions`, `/role-assignments`; GET/POST/PATCH | tenant admin/platform admin | POST key where applicable |
| API keys | `/api-keys`; GET/POST/DELETE | `api_keys:manage` | client key |
| Identity providers | `/identity-providers`; GET/POST/PATCH/DELETE | `identity:manage` | client key |
| Connectors/health | `/connectors`, `/connectors/{id}/test`, `/connectors/{id}/health`; CRUD/POST | `connectors:manage`, `connectors:read` | connector operation key |
| Events/search | `/events`, `/events/{id}`, `/events/search`; GET | `events:read` | search read-only |
| Ingest | `/ingest/{connector_id}`, `/ingest/import`; POST | per-connector token + HMAC signature | event `dedup_key`; batch key |
| Detections | `/detection-rules`; CRUD/enable | `detections:manage` | rule key/version |
| Alerts | `/alerts`, `/alerts/{id}`; GET/PATCH | `alerts:read/write` | alert dedup key |
| Incidents/evidence | `/incidents`, `/incidents/{id}`, `/incidents/{id}/evidence`; CRUD/POST | `incidents:read/write`, `evidence:read/write` | mutation key |
| Tasks/comments | `/tasks`, `/comments`; CRUD/POST | case permissions | client key |
| Assets/identities | `/assets`, `/identities`, `/business-services`; CRUD | `inventory:read/write` | external ID |
| Vulnerabilities/TI | `/vulnerabilities`, `/threat-intel`; CRUD/GET | `risk:read/write` | source fingerprint |
| AI investigations | `/ai-investigations`, `/ai-investigations/{id}/review`; POST/GET | `investigations:run/review` | investigation key |
| Response actions | `/response-actions`, `/approvals`; POST/GET | action permission plus approver | action key |
| Reports | `/reports`, `/reports/{id}/download`; POST/GET | `reports:read/create` | report key |
| Notifications | `/notifications`, `/notification-config`; GET/CRUD | `notifications:manage/read` | delivery key |
| Audit | `/audit-log`; GET | `audit:read` | read-only |
| Retention | `/retention-policies`; GET/PATCH | `retention:manage` | policy version |

Common: `429` rate limits include `Retry-After`; `401/403/404/409/422/429/500` use the error envelope. Resource versioning is URL-based; additive fields are compatible, breaking changes require a new version. Webhook ingress is separately rate-limited and rejects missing/invalid timestamped HMAC signatures; connector credentials are never returned.
