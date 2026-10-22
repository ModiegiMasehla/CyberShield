# CyberShield final QA report

## Scope and implementation

Reviewed the FastAPI/Python API, SQLAlchemy models, Alembic migration, React/TypeScript UI,
security services, configuration, Docker/CI setup, existing tests, documentation and lab fixtures.
The existing architecture and pinned dependencies are preserved. This is a bounded source review
and automated verification, not a certification or proof that every possible defect is absent.

## Confirmed fixes

1. Deleted `backend/app/api/config.py`. It duplicated the canonical `backend/app/config.py`,
   retained older configuration rules, and made `test_duplicate_config_module_is_gone` fail.
   No application caller imported the obsolete module. The original regression test is unchanged.
2. Password changes now enforce active account lockouts and reset expired lockouts before
   counting another failed attempt. Previously the endpoint counted guesses but kept accepting
   attempts after the threshold. Added a regression covering rejection, expiry and successful recovery.
3. TOTP validation rejects malformed/non-ASCII codes before constant-time string comparison,
   avoiding a TypeError/HTTP 500. Added an API regression for a six-character non-ASCII code.
4. Lab scanner and web-header address validation now accept IPv6 loopback (`::1`), which Python
   also classifies as reserved. Other reserved-address and metadata restrictions remain in place.
   Extended address-validation tests.
5. Session expiry resets the selected UI tab to Overview, preventing a later ordinary-user session
   from inheriting a stale staff-only tab. Added a full expiry/re-login component regression.
6. Frontend log uploads use the same 2,000,000-byte limit as the backend, rather than 2,097,152 bytes.
   Added tests at exactly the limit and one byte above it.

## Cleanup and documentation

- Added `.vscode/` to `.gitignore`.
- CI now upgrades pip and audits the installed test environment, including transitive and development dependencies.
- README setup instructions use Bash/Linux commands (`.venv/bin/python`) as the primary path, with Windows PowerShell notes retained. Node requirements were added, the obsolete-file deletion is explained with `rm -f` and `git add -u`, and destructive SQLite troubleshooting advice was replaced with backup guidance.
- The separate Git guide has a Linux (bash) version alongside the original PowerShell version.
- Final ZIP excludes Git metadata, virtual environments, dependencies, IDE directories, caches,
  databases, coverage output and compiled frontend output. Fictional sample logs and all required
  source, lockfiles, migrations, environment templates, CI and documentation are retained.
- The separate Git guide uses the observed main branch and origin metadata, and describes future
  commits only. No commits, pushes or remote repository changes were made.
- Copying over an existing checkout does not delete obsolete files: explicitly remove
  `backend/app/api/config.py` and stage its deletion. Preserve your existing `.git` history.

## Verification results

Environment: Windows, Python 3.12.14, Node.js 24.19.0 and npm 10.9.2. CI targets Python
3.12 and Node.js 22; Linux CI itself was not executed from this environment. The Linux command
forms in the README and in the reproduction commands below are the same checks with
`bin/python` in place of `Scripts/python.exe`; they were not separately executed on Linux
in this audit.

| Check | Observed result |
| --- | --- |
| Original-code regression reproduction | The reported duplicate-config test fails with DID NOT RAISE ImportError. The two added authentication regressions also fail against original code. |
| `pytest --cov=app --cov-report=term-missing` | 128 passed, 1 warning; 96% statement coverage. Passed in source and extracted archive. |
| `ruff check app tests alembic` | Passed. |
| `ruff format --check app tests alembic` | Passed: 36 files already formatted. |
| `bandit -r app -ll` | Passed: zero medium/high findings. |
| `python -m pip check` | Passed: no broken requirements. |
| Alembic upgrade / check / downgrade / upgrade | Passed on a disposable SQLite database; no new upgrade operations detected. |
| Startup on migrated schema | Health endpoint, demo admin login and repeated seed passed. |
| `pip-audit --local` | No known vulnerabilities after upgrading the isolated environment's pip from 25.0.1 to 26.2.1. |

The initial installed-environment audit reported advisories only for the bootstrap pip 25.0.1.
The separate `pip-audit -r requirements.txt` attempt failed during its isolated resolver step,
despite successful installation and pip check. CI and README now use `pip-audit --local`
after dependency installation, auditing the actual application, transitive and development packages
used by the test run. CI also upgrades pip first. No audit findings were ignored or suppressed.

The pytest warning is Starlette's deprecation of the httpx-backed TestClient. Tests pass;
the warning is not suppressed. The migrated-schema smoke check also emitted a weak-key warning
when using the intentionally weak default development secret; staging/production reject that default.
Bandit's three low-severity findings were reviewed: the literal token type `bearer`, the explicit
non-production default secret, and XML escaping in report generation (escaping text, not parsing XML).
These are documented rather than hidden with suppressions.

Frontend: `npm ci`, `npm run lint`, `npm test`, `npm run build`, and
`npm audit --audit-level=high` ran successfully. Final frontend suite: 15 passing tests.
The build includes `tsc --noEmit`. npm audit reported zero vulnerabilities at execution time.
The local sign-in screen was visually inspected in the in-app browser.

Archive verification: 94 required project files were packaged, re-extracted into a separate
workspace directory, and compared with source SHA-256 hashes. The extracted copy passed all
128 backend tests, backend static checks, all 15 frontend tests, ESLint and the production build.
Frontend dependencies were installed from the lockfile using `npm ci --offline` and the cache
populated by the earlier successful online installation. Final documentation/CI edits were then
repacked and hash-verified; application and test files remained identical to the tested copy.
The five-page Git guide was rendered to images and visually inspected.

## Remaining limitations and local follow-up

- Docker is unavailable here. Docker image builds, Compose startup, PostgreSQL integration and
  container image vulnerability scanning were not executed. On a Docker-capable machine run
  `docker compose config`, `docker compose up --build`, verify `/health` and the UI, and run the
  backend suite with TEST_DATABASE_URL pointing to an empty disposable PostgreSQL database.
- Browser visual inspection covers the sign-in screen only. Component tests exercise MFA prompting,
  role navigation, expiry/re-login, API errors and upload limits. npm also warns that the retained ESLint 9 release is out of support; npm audit reports no known vulnerabilities. A future major-version tooling upgrade is separate from this regression fix. A full live browser workflow across
  all roles, MFA devices and external network services remains a local acceptance check.
- No external public target scanning was performed. Network behavior tests use local or mocked targets.
- Existing educational-platform limitations remain: rate limiting and TOTP replay state are per process;
  TOTP secrets are unencrypted in the database; bearer tokens live in sessionStorage; private lab
  targets are intentionally reachable by staff; log parsing focuses on IPv4. See README for details.
- The checked-in accounts/passwords and lab samples are explicitly fictional demo fixtures. No real
  credentials were identified in the delivered source review; real .env files are excluded.
- Dependency audit results are a point-in-time check, not a guarantee about future advisories.

## Reproduction commands

From the repository root on Linux, WSL or macOS, create the environment if needed:

```bash
python3.12 -m venv backend/.venv
```

From `backend/`, using the environment's interpreter directly (no activation needed):

```bash
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest --cov=app --cov-report=term-missing
.venv/bin/python -m ruff check app tests alembic
.venv/bin/python -m ruff format --check app tests alembic
.venv/bin/python -m bandit -r app -ll
.venv/bin/python -m pip_audit --local
.venv/bin/python -m pip check
```

On Windows, use `.venv/Scripts/python.exe` in place of `.venv/bin/python`.

From `frontend/`, with Node.js 22.22.2 or newer and npm:

```bash
npm ci
npm run lint
npm test
npm run build
npm audit --audit-level=high
```

Use a disposable database for migration rollback checks; never downgrade a live database merely
as a verification step. The audit used a separate SQLite file for upgrade/check/downgrade/upgrade
and migrated-schema startup checks.