Verification Code: WTC-UTTW7KHZ

# CyberShield
### A Practical Cybersecurity Fundamentals & Security Monitoring Platform

CyberShield is a defensive cybersecurity portfolio project based on the supplied CyberShield specification. It demonstrates networking, Linux/system information, authentication, password security, cryptography concepts, safe network scanning, DNS/URL analysis, passive web-security checks, vulnerability assessment, log analysis, threat detection, incident response, RBAC, audit logging, reporting, secure coding, testing and Docker.

> **Authorization notice:** Only scan systems, networks, domains and applications that you own or have explicit permission to test. Unauthorized security testing may be illegal.

## Architecture

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, PostgreSQL, Alembic
- **Frontend:** React + TypeScript + Vite
- **Security:** Argon2id, TOTP MFA, JWT access tokens, RBAC, rate limiting, security headers
- **Testing:** pytest
- **DevSecOps:** Ruff, Bandit, GitHub/GitLab CI
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

The backend automatically creates the schema and seeds fictional demo data on startup.

## Local development

### Backend

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
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

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL=http://localhost:8000/api/v1` in `frontend/.env`.

## Tests

```bash
cd backend
pytest -q
```

## Security tooling

```bash
ruff check backend/app backend/tests
bandit -r backend/app -ll
```

## Demo credentials

Fictional development accounts are seeded:

- Admin: `admin@cybershield.local` / `CyberShield!Admin123`
- Analyst: `analyst@cybershield.local` / `CyberShield!Analyst123`
- User: `user@cybershield.local` / `CyberShield!User123`

Change these credentials before any non-demo deployment.

## Ten-stage Git workflow

See `STAGES_TO_PUSH.txt`. Each stage is intentionally independently understandable and ends with a suggested commit/push point.

## Safety boundaries

The scanners are designed for defensive, authorized use. The port scanner defaults to localhost/private lab targets, uses bounded concurrency and timeouts, and does not implement stealth, evasion, exploitation, credential attacks, mass scanning or destructive actions. URL and web checks are passive.

## Portfolio evidence

The repository includes:
- `docs/COMPETENCY_MATRIX.md`
- `docs/THREAT_MODEL.md`
- `docs/SECURITY_ARCHITECTURE.md`
- `docs/CYBERSECURITY_CONCEPTS.md`
- `security-lab/`
- `tests/`
- CI configuration

## Limitations

This is a portfolio/lab platform, not a certified SIEM, EDR, penetration-testing suite or security certification. Detection is rule-based and sample-data driven. External CVE feeds are intentionally optional; local knowledge data keeps the application functional without API keys.
