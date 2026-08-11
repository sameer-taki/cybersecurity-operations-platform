#!/usr/bin/env bash
set -euo pipefail

cp -n .env.example .env
uv sync
docker compose -f infra/docker-compose.yml up --build -d
docker compose -f infra/docker-compose.yml run --rm seed
