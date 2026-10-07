# CyberShield Threat Model

## Assets
- User accounts
- Authentication secrets
- Security alerts
- Incident records
- Audit logs
- Assessment results
- Database credentials

## Threat actors
- Unauthenticated attacker
- Compromised user
- Malicious insider
- Automated internet scanner

## Attack surfaces
- Login/register API
- Authenticated API endpoints
- File upload for logs
- URL/web analysis endpoints
- Database
- Frontend

## STRIDE examples
- **Spoofing:** stolen credentials → Argon2id + MFA + lockout.
- **Tampering:** unauthorized incident changes → RBAC + audit logs.
- **Repudiation:** disputed administrative action → audit records.
- **Information disclosure:** verbose errors → sanitized API errors and externalized secrets.
- **Denial of service:** unlimited scans/uploads → size limits, timeouts and bounded concurrency.
- **Elevation of privilege:** role manipulation → server-side role checks.

## Residual risk
The project is educational. JWT, infrastructure, dependencies and deployment configuration still require professional hardening before production use.
