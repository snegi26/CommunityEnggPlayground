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
| `VAULT_PROVIDER` | `aws_kms` in production; `local` only for development |
| `VAULT_LOCAL_MASTER_KEY` | Base64 32-byte key for the local vault provider (no default) |
| `VAULT_KMS_KEY_ID`, `VAULT_AWS_REGION` | KMS key used to wrap per-secret data keys |
| `ANTHROPIC_API_KEY`, `PASSPORT_DRAFTING_MODEL` | Claim drafting (default model `claude-sonnet-5-5`) |
| `AWS_PLATFORM_PRINCIPAL_ARN` | Our principal that customer roles trust |
| `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` | GitHub App |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | Google Workspace OAuth client |

In production, load the platform credentials (GitHub App private key, Google client
secret) and the vault settings from AWS Secrets Manager, never from committed files. Rotate
them by issuing a new credential, deploying it, and then revoking the old one; vault
ciphertext does not need re-encryption because each secret's data key is wrapped by KMS.

Connector customer onboarding uses `deploy/aws-readonly-role.yaml` (SecurityAudit plus a
required external id).

