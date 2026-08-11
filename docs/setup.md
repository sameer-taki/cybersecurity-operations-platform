# Phase 1 local setup

Prerequisites: Docker with Compose v2, `uv`, and Git.

```bash
cp .env.example .env
uv sync
docker compose -f infra/docker-compose.yml up --build -d
docker compose -f infra/docker-compose.yml run --rm seed
```

The API is at `http://localhost:8000`; health is `GET /health`. The stack contains PostgreSQL 16, MinIO, Redis, the migration step, API, and seed service. `docker compose ... down -v` removes local data.

The API tenant-registry path uses the dedicated `platform_admin_login` deployment
role; ordinary tenant-plane requests use `app_api_login`. The DDL owner is not
used for registry reads or writes.

Development-only seeded users:

| Tenant | Email | Password |
|---|---|---|
| `dev-tenant-1` | `admin1@example.com` | `DevOnly-ChangeMe-123!` |
| `dev-tenant-2` | `admin2@example.com` | `DevOnly-ChangeMe-123!` |

These credentials are local fixtures only and must never be used outside development. No ingestion endpoints or production connectors exist in Phase 1.
