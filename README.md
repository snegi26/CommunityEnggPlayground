# Compliance Freshness Passport

Tracks whether SOC 2 and ISO 27001 policies and evidence are still current and still true,
by checking what policies promise against read-only views of an organization's systems.
The plan lives in `docs/plans/2026-10-30-1351-feat-compliance-freshness-passport-plan.md`.

## Local setup

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), and Postgres 16.

```bash
docker compose up -d db
```

```bash
uv sync
```

```bash
cp .env.example .env
```

```bash
uv run alembic upgrade head
```

Without Docker, run `deploy/postgres/init-roles.sql` against a local Postgres 16 as a superuser.

## Running

Web app:

```bash
uv run uvicorn passport.app:create_app --factory --reload
```

Background worker (scheduled checks, drafting jobs):

```bash
uv run python -m passport.worker
```

## Checks

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src && uv run pytest
```

## Configuration

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Application role: not a table owner, no `BYPASSRLS` |
| `MIGRATION_DATABASE_URL` | Table-owner role used only by Alembic and test fixtures |
| `APP_DB_ROLE` | Name of the application role that migrations grant privileges to |
