# CyberShield
### A Practical Cybersecurity Fundamentals & Security Monitoring Platform

CyberShield is a defensive cybersecurity portfolio project based on the supplied CyberShield specification. It demonstrates networking, Linux/system information, authentication, password security, cryptography concepts, safe network scanning, DNS/URL analysis, passive web-security checks, vulnerability assessment, log analysis, threat detection, incident response, RBAC, audit logging, reporting, secure coding, testing and Docker.

> **Authorization notice:** Only scan systems, networks, domains and applications that you own or have explicit permission to test. Unauthorized security testing may be illegal.

## Architecture

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy, PostgreSQL, Alembic
- **Frontend:** React + TypeScript + Vite
- **Security:** Argon2id, TOTP MFA, JWT access tokens, RBAC, rate limiting, security headers
- **Testing:** pytest (backend, runs on SQLite or PostgreSQL), Vitest + Testing Library (frontend), ESLint with accessibility rules
- **DevSecOps:** Ruff, Bandit, pip-audit and npm audit, run locally (see below) and by `.github/workflows/ci.yml`
- **Reports:** PDF generation with ReportLab
- **Lab:** Safe localhost-oriented scanners and fictional sample data

## Quick start with Docker

```bash
cp .env.example .env
docker compose up --build
```

Then open:
- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs
- API health: http://localhost:8000/health

On start the backend applies the Alembic migrations (`AUTO_CREATE_SCHEMA=false` in Compose) and, in development, seeds fictional demo data. The frontend container runs the Vite dev server; build `frontend/` with `npm run build` and serve `dist/` behind a reverse proxy for anything beyond local use.

## Local development

### Backend

The examples below use Bash. On Windows PowerShell, use `py -3.12 -m venv .venv`,
then `.\.venv\Scripts\Activate.ps1`; set environment variables with
`$env:DATABASE_URL = "sqlite:///./cybershield.db"` and
`$env:SECRET_KEY = "replace-with-a-long-development-secret"`.

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

For a local SQLite development database:

```bash
export DATABASE_URL=sqlite:///./cybershield.db
export SECRET_KEY='replace-with-a-long-development-secret'
uvicorn app.main:app --reload
```

### Frontend

Use Node.js 22.12+ (CI uses Node.js 22) and npm.

```bash
cd frontend
npm ci
npm run dev
```

Other scripts: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build` (type-checks, then builds).

Set `VITE_API_URL=http://localhost:8000/api/v1` in `frontend/.env`.

## Database migrations (Alembic)

```bash
cd backend
alembic upgrade head      # apply schema
alembic downgrade base    # roll back
```

Docker Compose sets `AUTO_CREATE_SCHEMA=false` and runs `alembic upgrade head` on start. For quick local SQLite development the app creates the schema itself (`AUTO_CREATE_SCHEMA=true`, the default). Use one approach per database, not both.

## Production notes

- `ENVIRONMENT=production` refuses to start with the default or a short `SECRET_KEY` (32+ random characters required), disables `/docs`, enables HSTS and does **not** seed the demo accounts (override with `SEED_DEMO_DATA=true` only for demos).
- `ENVIRONMENT` must be `development`, `test`, `staging` or `production`; any other value (for example `prod`) stops the app at start-up instead of silently running with development defaults. `staging` has the same secret and CORS rules as production and does not seed demo data.
- Behind a reverse proxy, start uvicorn with `--proxy-headers` and set `FORWARDED_ALLOW_IPS` to the proxy address; otherwise every client shares the proxy's IP and therefore one rate-limit bucket.
- Rate limiting (`RATE_LIMIT_PER_MINUTE`, `LOGIN_RATE_LIMIT_PER_MINUTE`) is in-memory per process; use a shared store (e.g. Redis) or a reverse proxy when running several workers.

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest --cov=app                      # SQLite (default, throw-away file)
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/empty_db pytest   # PostgreSQL

cd ../frontend && npm test
```

## Security tooling

```bash
ruff check backend/app backend/tests backend/alembic
ruff format --check backend/app backend/tests backend/alembic
bandit -r backend/app -ll
pip-audit --local
```

Run these commands with the backend virtual environment activated and
`requirements-dev.txt` installed. The audit checks the installed application,
transitive dependencies, and development tools used by the test run, matching CI.

## Demo credentials

Fictional development accounts are seeded:

- Admin: `admin@cybershield.local` / `CyberShield!Admin123`
- Analyst: `analyst@cybershield.local` / `CyberShield!Analyst123`
- User: `user@cybershield.local` / `CyberShield!User123`

Change these credentials before any non-demo deployment.

## Safety boundaries

The scanners are designed for defensive, authorized use. The port scanner defaults to localhost/private lab targets, uses bounded concurrency and timeouts, and does not implement stealth, evasion, exploitation, credential attacks, mass scanning or destructive actions. URL and web checks are passive.

## Portfolio evidence

The repository includes:
- `documents/COMPETENCY_MATRIX.md`
- `documents/THREAT_MODEL.md`
- `documents/SECURITY_ARCHITECTURE.md`
- `documents/CYBERSECURITY_CONCEPTS.md`
- `security-lab/`
- `backend/tests/` and `frontend/src/test/`
- CI configuration (`.github/workflows/ci.yml`)

## Limitations

This is a portfolio/lab platform, not a certified SIEM, EDR, penetration-testing suite or security certification. Detection is rule-based and sample-data driven. External CVE feeds are intentionally optional; local knowledge data keeps the application functional without API keys.

Known limitations:

- Rate-limit and TOTP-replay state live in process memory; with several workers use a shared store.
- TOTP secrets are stored unencrypted in the database; protect database access and backups, or add application-level encryption before real use.
- Access tokens are bearer JWTs kept in `sessionStorage` and cannot be revoked individually (a password change revokes all of a user's tokens). Serve the frontend with a strict Content-Security-Policy.
- Header checks and port scans are staff-only and audited, but they can reach private and loopback addresses by design (lab use); metadata and link-local ranges are blocked.
- Log analysis understands IPv4 addresses and the formats in `security-lab/sample-logs`; it is a teaching tool, not a SIEM.

## Troubleshooting

- **`ValidationError ... environment`** at start-up: `ENVIRONMENT` is not one of development/test/staging/production.
- **`SECRET_KEY must be a random value`**: set a 32+ character secret (see `.env.example`) when `ENVIRONMENT` is staging or production.
- **Existing token suddenly rejected after upgrading, or after a password change**: tokens are bound to the password they were issued for; sign in again.
- **`no such column` / missing table on a local SQLite file**: back up the database first. Run `alembic upgrade head` on a database managed by Alembic. For disposable demo data created with `AUTO_CREATE_SCHEMA=true`, move the old database aside and restart to create a new one.
- **Frontend shows "Cannot reach the server"**: start the backend and check `VITE_API_URL` and `CORS_ORIGINS`.
- **Accounts locked**: five failed sign-ins lock an account for 15 minutes (`MAX_FAILED_LOGINS`, `LOCKOUT_MINUTES`).
- **`test_duplicate_config_module_is_gone` fails with `DID NOT RAISE ImportError`**:
  remove the obsolete `backend/app/api/config.py` from your checkout. The only settings
  module is `backend/app/config.py`; do not restore the duplicate or weaken the test.
  When copying this submission over an existing checkout, remember that copying files
  does not remove obsolete files. Stage the deletion with
  `git add -u -- backend/app/api/config.py`.

## Final QA

See `documents/FINAL_QA_REPORT.md` for changes, executed checks, and remaining
verification limits. The submission archive excludes Git metadata, virtual
environments, local IDE settings, caches, and build output. Apply its changes to
your existing repository to preserve its history; no commits or pushes were
performed as part of the audit.
