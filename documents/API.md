# API Quick Reference

Base path `/api/v1`. Protected endpoints need `Authorization: Bearer <token>`. Roles: `ADMIN`, `SECURITY_ANALYST` (both "staff"), `USER`.

| Method and path | Access | Notes |
| --- | --- | --- |
| `GET /health` | public | Also available at `/health` |
| `POST /auth/register` | public | 201; 400 with password-policy messages; 409 if the email exists |
| `POST /auth/login` | public | Body `{email, password, otp?}`. 401 `MFA verification required` when MFA is on and `otp` is missing/wrong; 423 when locked |
| `GET /auth/me` | any user | `{id, email, role, mfa_enabled}` |
| `POST /auth/password/change` | any user | Revokes all existing tokens of the user; wrong current password counts toward lockout |
| `POST /auth/mfa/setup`, `POST /auth/mfa/enable` | any user | TOTP codes are single-use |
| `GET /dashboard` | any user | |
| `POST /tools/password/analyze`, `POST /tools/url/analyze` | password: public, url: any user | |
| `GET /tools/dns/{domain}` | any user | |
| `GET /tools/network/info` | staff | Was any user before 1.1.0 (leaked host details to self-registered accounts) |
| `POST /tools/network/scan` | staff | Lab ranges only; denied attempts are audited |
| `POST /tools/web/headers` | staff | Blocked ranges are audited; the validated IP is the one connected to |
| `POST /tools/logs/analyze?save_alerts=bool` | staff | Multipart field `file` (max 2 MB); audited |
| `GET /alerts`, `PATCH /alerts/{id}` | staff | PATCH: omitted fields are untouched; `assigned_analyst_id: null` unassigns; null `status` is rejected (422) |
| `GET /incidents`, `POST /incidents`, `PATCH /incidents/{id}` | staff | List now also returns `description`, `resolution`, `assigned_analyst_id`, `created_at` |
| `GET /vulnerabilities` | any user | |
| `GET /audit-logs?limit=` | admin | |
| `GET /reports/security.pdf` | staff | |

Statuses. Incident: `OPEN, INVESTIGATING, CONTAINED, ERADICATED, RECOVERED, CLOSED`. Alert: `NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE`.

Errors are JSON `{"detail": ...}` where detail is a string or, for validation failures, a list. Unhandled errors return `{"detail": "Internal server error", "request_id": "..."}`.

Every response carries an `X-Request-ID` header (a client-supplied value matching `[A-Za-z0-9._-]{8,64}` is echoed, otherwise one is generated); the same id appears in the access log.
