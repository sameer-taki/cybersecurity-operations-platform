#!/usr/bin/env bash
set -euo pipefail

[ -f .env ] || cp .env.example .env
uv sync
docker compose -f infra/docker-compose.yml up --build -d
docker compose -f infra/docker-compose.yml run --rm seed
