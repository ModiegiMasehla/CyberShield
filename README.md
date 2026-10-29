# CyberShield
### A Practical Cybersecurity Fundamentals & Security Monitoring Platform

CyberShield is a defensive cybersecurity portfolio project. It demonstrates networking, Linux/system information, authentication, password security, cryptography concepts, safe network scanning, DNS/URL analysis, passive web-security checks, vulnerability assessment, log analysis, threat detection, incident response, RBAC, audit logging, reporting, secure coding, testing and Docker.

> **Authorization notice:** Only scan systems, networks, domains and applications that you own or have explicit permission to test. Unauthorized security testing may be illegal. The built-in scanners are meant for localhost and private lab targets.

## Architecture

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy, PostgreSQL, Alembic
- **Frontend:** React + TypeScript + Vite
- **Security:** Argon2id, TOTP MFA, JWT access tokens, RBAC, rate limiting, security headers
- **Testing:** pytest (SQLite or PostgreSQL), Vitest + Testing Library, ESLint with accessibility rules
- **DevSecOps:** Ruff, Bandit, pip-audit and npm audit, run locally and by `.github/workflows/ci.yml`
- **Reports:** PDF generation with ReportLab
- **Lab:** Safe localhost-oriented scanners and fictional sample data

## Run it from scratch (Linux)

Written for Pop!_OS / Ubuntu with Bash. Follow the steps in order; each one says where to run it and what a good result looks like. 

Ports used: frontend `5173`, API `8000`, both bound to `127.0.0.1` only. Commands run from the project root unless the step says otherwise.

### Step 0. Check your tools

Run from: project root.

```bash
cd ~/Desktop/Electives/CyberSecurity/CyberShield
python3.12 --version
node --version
npm --version
docker --version
docker compose version
git --version
```

Python must be 3.12 or newer, Node.js 22.12 or newer, and Docker needs the Compose plugin. Pop!_OS 22.04 ships Python 3.10, so install 3.12 if it is missing.

Install or fix anything missing:

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12 python3.12-venv
nvm install 22 && nvm use 22
sudo usermod -aG docker "$USER"   # then log out and back in
```

**Expected result:** Every command prints a version. Python is 3.12+, Node is 22.12+.

### Step 1. Start from a clean slate

Run from: project root.

```bash
docker compose down -v --remove-orphans --rmi local 2>/dev/null || true
docker rm -f cs-test-pg 2>/dev/null || true
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f vite 2>/dev/null || true

rm -rf backend/.venv backend/.pytest_cache backend/.ruff_cache backend/htmlcov
rm -f backend/.coverage backend/*.db
find backend -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf frontend/node_modules frontend/dist frontend/.vite
rm -f .env frontend/.env
rm -f backend/app/api/config.py

ss -ltn | grep -E ':(5173|8000|8001|5433)\b' || echo "ports free"
docker volume ls | grep -i cybershield || echo 'no cybershield volumes'
```

This removes everything earlier runs left behind: containers, the database volume, built images, virtual environment, node_modules, build output, caches, local SQLite files, .env files and the obsolete duplicate config module. Source code, git history and .env.example are untouched. If a port is still listed, stop whatever owns it before continuing.

**Expected result:** Prints "ports free" and "no cybershield volumes".

### Step 2. Create the backend environment

Run from: project root, then backend/.

```bash
python3.12 -m venv backend/.venv
cd backend
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip check
```

Calling .venv/bin/python directly means the environment never needs activating. Upgrading pip first matters because pip-audit flags old pip versions. The remaining backend steps run from backend/.

**Expected result:** No ERROR lines, and pip check prints "No broken requirements found."

### Step 3. Backend tests and security checks

Run from: backend/.

```bash
.venv/bin/python -m pytest --cov=app --cov-report=term-missing
.venv/bin/python -m ruff check app tests alembic
.venv/bin/python -m ruff format --check app tests alembic
.venv/bin/python -m bandit -r app -ll
.venv/bin/python -m pip_audit --local
```

pytest runs the suite on a throw-away SQLite file with coverage. ruff lints and checks formatting, bandit scans the source for medium and high severity issues, and pip-audit checks installed packages against known vulnerabilities (needs internet).

**Expected result:** All tests pass (the QA audit saw 128 passed and about 96% coverage; your numbers may differ if tests were added). ruff and bandit are clean, pip-audit reports no known vulnerabilities. One Starlette TestClient deprecation warning is normal.

### Step 4. Frontend checks

Run from: frontend/.

```bash
cd ../frontend
npm ci
npm run lint
npm run typecheck
npm test
npm run build
npm audit --audit-level=high
cd ..
```

npm ci installs the exact versions in package-lock.json. Lint includes accessibility rules, the build type-checks first, and the audit fails only on high or critical advisories.

**Expected result:** Lint clean, tests pass (15 in the QA audit), build completes, npm audit reports 0 vulnerabilities. An ESLint 9 support notice is a known, harmless warning.

### Step 5. Migration round trip

Run from: backend/.

```bash
cd backend
(
export DATABASE_URL=sqlite:///./migration_check.db
export SECRET_KEY=replace-with-a-long-development-secret
export AUTO_CREATE_SCHEMA=false
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic check
.venv/bin/python -m alembic downgrade base
.venv/bin/python -m alembic upgrade head
rm -f migration_check.db
)
```

This proves every migration applies, matches the models, and can be reversed. The parentheses run it in a subshell, so the exported variables disappear afterwards and cannot leak into later steps. AUTO_CREATE_SCHEMA=false lets Alembic alone build the schema. Never run downgrade on a database you care about.

**Expected result:** Upgrade lines appear twice, alembic check reports no new upgrade operations, and there are no errors.

### Step 6. Run the API locally and probe it

Run from: backend/ (terminal 1), anywhere (terminal 2).

```bash
# Terminal 1, inside backend/
(
export DATABASE_URL=sqlite:///./local_check.db
export SECRET_KEY=replace-with-a-long-development-secret
export AUTO_CREATE_SCHEMA=false
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m uvicorn app.main:app --port 8000
)

# Terminal 2
curl -i http://localhost:8000/health
curl -s http://localhost:8000/
curl -s http://localhost:8000/openapi.json | python3 -m json.tool | grep '"/api'
```

This tests the app on a migrated SQLite database before Docker adds more moving parts. Then open http://localhost:8000/docs, click Authorize and sign in as admin@cybershield.local. A successful login proves the database, seeding and password hashing work together. Stop the server with Ctrl+C. Keep local_check.db for Step 7. A weak-key warning in the server log is expected in development.

**Expected result:** /health returns HTTP 200 with {"status":"ok","service":"cybershield"} and security headers such as X-Content-Type-Options. The route list shows the real /api paths.

### Step 7. Check that unsafe configuration is refused

Run from: backend/.

```bash
ENVIRONMENT=prod .venv/bin/python -m uvicorn app.main:app --port 8001
ENVIRONMENT=production .venv/bin/python -m uvicorn app.main:app --port 8001

ENVIRONMENT=production \
SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
DATABASE_URL=sqlite:///./local_check.db AUTO_CREATE_SCHEMA=false \
.venv/bin/python -m uvicorn app.main:app --port 8001 &
sleep 4
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8001/docs
kill %1
rm -f local_check.db
cd ..
```

A refusal here is the secure behaviour. The first command fails because prod is not a valid environment name. The second fails because production rejects the default or a short SECRET_KEY. The third starts with a strong generated key, and /docs returns 404 because docs are disabled in production.

**Expected result:** The first two commands fail at start-up. The third prints 404.

### Step 8. Start everything with Docker

Run from: project root, terminal 1.

```bash
unset DATABASE_URL SECRET_KEY AUTO_CREATE_SCHEMA ENVIRONMENT TEST_DATABASE_URL
cp .env.example .env
docker compose config > /dev/null && echo "compose file OK"
docker compose up --build
```

The unset line makes sure no leftover shell variable overrides what Compose reads from .env. Compose starts postgres first, then the backend (applies Alembic migrations and seeds the fictional demo data in development), then the frontend. Keep this terminal open. Never commit .env.

**If it fails:** If Compose stops with a missing healthcheck or a failed dependency, add a HEALTHCHECK that calls /health to backend/Dockerfile, or a healthcheck block to the backend service in docker-compose.yml. The frontend waits for the backend to be healthy.

**Expected result:** Images build, postgres becomes healthy, backend logs the Alembic upgrade lines, and the frontend serves on port 5173.

### Step 9. Smoke-test the running containers

Run from: project root, terminal 2.

```bash
cd ~/Desktop/Electives/CyberSecurity/CyberShield
docker compose ps
curl -i http://localhost:8000/health
curl -sI http://localhost:8000/docs | head -n 1
curl -sI http://localhost:5173 | head -n 1
docker compose logs backend | grep -i -E "alembic|upgrade|error" | head
```

postgres should be healthy and backend and frontend running. The log filter shows the migration lines and any errors.

**Expected result:** HTTP 200 from /health, /docs and the frontend. Alembic upgrade lines appear and there are no tracebacks.

### Step 10. Run the test suite against PostgreSQL

Run from: backend/, terminal 2.

```bash
cd backend
docker run --rm -d --name cs-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=empty_db -p 5433:5432 postgres:16-alpine
until docker exec cs-test-pg pg_isready -U postgres; do sleep 1; done
TEST_DATABASE_URL=postgresql+psycopg://postgres:test@localhost:5433/empty_db .venv/bin/python -m pytest
docker stop cs-test-pg
cd ..
```

This uses a separate, empty, disposable Postgres container on port 5433, so it cannot touch the real database. The container deletes itself when stopped.

**Expected result:** The same test suite passes on PostgreSQL as on SQLite.

### Step 11. Browser acceptance walkthrough

Run from: browser at http://localhost:5173.


Work through every row. Demo accounts are listed under Demo credentials.

- Admin: `admin@cybershield.local` / `CyberShield!Admin123`
- Analyst: `analyst@cybershield.local` / `CyberShield!Analyst123`
- User: `user@cybershield.local` / `CyberShield!User123`


| # | Do this |                                                                                            | Expect |
|---|---|---|
| 1 | Sign in as admin@cybershield.local                                                   | Dashboard loads and all staff tabs are visible |
| 2 | Visit scans, DNS/URL, logs, threats, incidents, reports and audit                    | No error banners; data displays |
| 3 | Upload a sample log from security-lab/sample-logs/                                   | Analysis results appear; a file over 2,000,000 bytes is rejected |
| 4 | Run a port scan against 127.0.0.1, then try a metadata address (169.254.169.254)     | Localhost is allowed; metadata and link-local targets are blocked |
| 5 | Generate a PDF report and open it                                                    | A valid PDF downloads |
| 6 | Sign out and sign in as user@cybershield.local                                       | Staff-only tabs are not shown |
| 7 | Sign in as analyst@cybershield.local                                                 | Analyst features visible; admin-only features hidden |
| 8 | Enable MFA (TOTP) on the analyst account with an authenticator app                   | Next login asks for the 6-digit code; a wrong code is rejected |
| 9 | Stop the backend with docker compose stop backend while the page is open             | UI shows "Cannot reach the server"; docker compose start backend restores it |
| 10 | Enter a wrong password 5 times on user@cybershield.local (do this last)             | Account locks for 15 minutes; a 429 appears past 10 login attempts a minute |

**Expected result:** See the table.

### Step 12. Stop, reset and run it again

Run from: project root.

```bash
docker compose stop
docker compose down
docker compose down -v
docker compose up -d
```

stop pauses containers and keeps data, down removes containers but keeps the database volume, and down -v also deletes the database so the demo data is re-seeded on the next start. Use down -v after the lockout and MFA tests to get fresh demo accounts.

**Expected result:** After down -v and up -d, the demo accounts work again.

### Final checklist

| Step | Pass criteria |
|---|---|
| 0 | Tools present |
| 1 | Ports free, no old volumes, obsolete `config.py` gone |
| 3 | Backend tests pass; ruff, bandit and pip-audit clean |
| 4 | Lint, tests, build and npm audit pass |
| 5 | Alembic up, check, down, up all succeed |
| 6 / 7 | Local API healthy; unsafe config refused; `/docs` is 404 in production |
| 8 / 9 | Compose starts all three services; health, docs and UI return 200 |
| 10 | Same tests pass on PostgreSQL |
| 11 | All 10 browser checks behave as expected |

## Daily use

```bash
cd ~/Desktop/Electives/CyberSecurity/CyberShield
cp .env.example .env              # first time only
docker compose up --build         # first time, or after code changes
docker compose up -d              # later runs, in the background
docker compose logs -f backend    # live backend output
docker compose ps                 # container state
docker compose stop               # pause, keep data
docker compose down               # remove containers, keep database volume
docker compose down -v            # remove containers and database
```

| Address | Purpose |
|---|---|
| http://localhost:5173 | Web application |
| http://localhost:8000/docs | API documentation (disabled in production) |
| http://localhost:8000/health | Backend health check |

## Run without Docker (development)

```bash
# Terminal 1
cd backend
export DATABASE_URL=sqlite:///./cybershield.db
export SECRET_KEY='replace-with-a-long-development-secret'
.venv/bin/python -m uvicorn app.main:app --reload --port 8000

# Terminal 2
cd frontend
echo 'VITE_API_URL=http://localhost:8000/api/v1' > .env
npm run dev
```

Do not use the `DATABASE_URL` line from `.env.example` here; it points at the Docker host name `postgres`. Run `unset DATABASE_URL SECRET_KEY` in a terminal before using Docker Compose from it.

## Demo credentials

Fictional development accounts, seeded in development only:

- Admin: `admin@cybershield.local` / `CyberShield!Admin123`
- Analyst: `analyst@cybershield.local` / `CyberShield!Analyst123`
- User: `user@cybershield.local` / `CyberShield!User123`

Change these before any non-demo deployment. Staging and production do not create them unless `SEED_DEMO_DATA=true`.

## Configuration (`.env`)

| Setting | Meaning | Default |
|---|---|---|
| `ENVIRONMENT` | development, test, staging or production; any other value stops start-up | development |
| `SECRET_KEY` | Signs tokens; staging and production need 32+ random characters | dev placeholder |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Login lifetime | 60 |
| `CORS_ORIGINS` | Front-end origin allowed to call the API | http://localhost:5173 |
| `RATE_LIMIT_PER_MINUTE` | General request limit per client | 60 |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | Login attempt limit per client | 10 |
| `MAX_FAILED_LOGINS` | Failed logins before lockout | 5 |
| `LOCKOUT_MINUTES` | Lockout length | 15 |
| `SEED_DEMO_DATA` | Create fictional demo data and accounts | true in development |
| `AUTO_CREATE_SCHEMA` | App builds tables itself (SQLite dev); Docker forces false and uses Alembic. Use one method per database | true (local) |
| `POSTGRES_PASSWORD` | Docker database password; not in `.env.example`, add it to change it | cybershield |
| `LOG_LEVEL` | Logging amount | INFO |

## Production notes

- `ENVIRONMENT=production` refuses to start with the default or a short `SECRET_KEY`, disables `/docs`, enables HSTS and does not seed demo accounts. Generate a key with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
- `staging` has the same secret and CORS rules as production and does not seed demo data.
- The frontend container runs the Vite dev server. For real use, run `npm run build` and serve `dist/` behind a reverse proxy with a strict Content-Security-Policy.
- Behind a reverse proxy, start uvicorn with `--proxy-headers` and set `FORWARDED_ALLOW_IPS`; otherwise every client shares one rate-limit bucket.
- Rate limiting and TOTP replay state live in process memory; use Redis or a reverse proxy with several workers.

## Safety boundaries

The port scanner defaults to localhost and private lab targets, uses bounded concurrency and timeouts, and does not implement stealth, evasion, exploitation, credential attacks, mass scanning or destructive actions. URL and web checks are passive.

## Portfolio evidence

- `documents/COMPETENCY_MATRIX.md`
- `documents/THREAT_MODEL.md`
- `documents/SECURITY_ARCHITECTURE.md`
- `documents/CYBERSECURITY_CONCEPTS.md`
- `documents/FINAL_QA_REPORT.md`
- `security-lab/`
- `backend/tests/` and `frontend/src/test/`
- `.github/workflows/ci.yml`

## Limitations

This is a portfolio/lab platform, not a certified SIEM, EDR or penetration-testing suite. Detection is rule-based and sample-data driven. External CVE feeds are optional.

- Rate-limit and TOTP-replay state live in process memory.
- TOTP secrets are stored unencrypted in the database; protect database access and backups, or add application-level encryption before real use.
- Access tokens are bearer JWTs in `sessionStorage` and cannot be revoked individually (a password change revokes all of a user's tokens).
- Header checks and port scans are staff-only and audited, but can reach private and loopback addresses by design; metadata and link-local ranges are blocked.
- Log analysis understands IPv4 addresses and the formats in `security-lab/sample-logs`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ValidationError` about environment | `ENVIRONMENT` must be development, test, staging or production (not `prod`) |
| `SECRET_KEY must be a random value` | Set a 32+ character key in staging or production |
| "Cannot reach the server" in the UI | Start the backend; check `VITE_API_URL` and `CORS_ORIGINS` |
| Token suddenly rejected | Tokens are tied to the password; sign in again |
| Account locked | Wait 15 minutes, or `docker compose down -v` then `docker compose up -d` |
| `no such column` / missing table (SQLite) | Back up the file, `mv cybershield.db cybershield.db.bak`, restart; or `alembic upgrade head` if Alembic manages it |
| `permission denied` from Docker | `sudo usermod -aG docker "$USER"`, then log out and in |
| Port already in use | `sudo lsof -i :8000` (or `:5173`) and stop the process |
| `DID NOT RAISE ImportError` in a test | `rm -f backend/app/api/config.py` (see Step 1) |
| Compose dependency or healthcheck error | Add a backend healthcheck calling `/health` (see Step 8) |
| HTTP 500 from the API | The body has a `request_id`; search the backend log for it |
| `.venv/Scripts/python.exe: No such file` | On Linux use `.venv/bin/python` |