# Security Architecture

```text
User
  |
  v
React Frontend
  |
  v
FastAPI API
  |
  +--> Authentication / JWT / TOTP
  |
  +--> RBAC / Input Validation / Rate Limits
  |
  +--> Security Services
  |       +-- Password Analyzer
  |       +-- Network Scanner
  |       +-- DNS Analyzer
  |       +-- URL Analyzer
  |       +-- Web Header Checker
  |       +-- Log Analyzer / Detection
  |
  +--> PostgreSQL
  |
  +--> Audit Logging / Reports
```

Security controls:
- Authentication
- Authorization
- Validation
- Password hashing
- MFA
- Rate limiting/lockout
- Request limits
- Timeouts
- Audit logging
- Secure configuration
- CI security checks
