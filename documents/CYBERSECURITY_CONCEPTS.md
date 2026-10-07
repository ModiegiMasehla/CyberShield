# CyberShield Cybersecurity Concepts

## CIA Triad
- **Confidentiality:** restrict sensitive data to authorized users.
- **Integrity:** prevent unauthorized modification and preserve trustworthy records.
- **Availability:** keep services and security information usable.

CyberShield demonstrates these through authentication/RBAC, audit records, database constraints, rate limits, bounded scans and controlled error handling.

## Networking
The network module exposes local hostname/IP information. The safe scanner works against localhost/private lab addresses, uses bounded concurrency and timeouts, and maps common ports to services.

## Linux and operating-system security
The backend records host information using standard Python system interfaces. The project structure and Docker services demonstrate process/service isolation and environment-variable configuration.

## Authentication and authorization
Passwords are stored using Argon2id verifiers. Login has lockout behavior and optional TOTP MFA. JWTs carry identity and role claims. API dependencies enforce RBAC.

## Cryptography
Hashing is used for password verification. TOTP uses a standard implementation. The project deliberately avoids custom cryptography.

## Web security
The URL analyzer provides heuristic indicators. The passive web checker inspects HTTPS, security headers, cookies, redirect behavior and server disclosure without exploitation.

## Vulnerability assessment
Findings have severity, description, impact, recommendation and evidence. Local sample vulnerabilities demonstrate risk-based remediation.

## Security monitoring
Authentication logs can be uploaded and analyzed for repeated failed logins and sensitive-path activity. A rule engine converts thresholds into alerts.

## Incident response
Incidents support OPEN → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED. Analysts can assign and resolve incidents.

## Risk management
Findings use severity and recommendations. The dashboard security score is transparent and educational, not a certification.

## Secure coding
Pydantic validates requests, SQLAlchemy provides parameterized ORM access, error responses avoid stack traces, uploaded logs are size-limited, scanner targets are constrained and secrets are externalized.

## Ethical boundaries
CyberShield does not implement malware, credential theft, keylogging, persistence, stealth/evasion, exploit deployment, DDoS, mass scanning or credential stuffing.
