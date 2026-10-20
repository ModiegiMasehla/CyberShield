from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Alert, AuditLog, Incident, Role, User, Vulnerability
from ..schemas import (
    AlertUpdateIn,
    IncidentIn,
    IncidentUpdateIn,
    LoginIn,
    MFACodeIn,
    PasswordAnalyzeIn,
    PasswordChangeIn,
    PortScanIn,
    RegisterIn,
    URLAnalyzeIn,
)
from ..security import (
    burn_password_check,
    create_token,
    current_user,
    hash_password,
    new_totp_secret,
    require_roles,
    validate_password_policy,
    verify_password,
    verify_totp,
)
from ..services.audit import audit
from ..services.dns_analyzer import is_valid_domain
from ..services.dns_analyzer import lookup as dns_lookup
from ..services.log_analyzer import analyze_lines
from ..services.network import network_info, scan_ports
from ..services.password_analyzer import analyze_password
from ..services.reports import security_report
from ..services.url_analyzer import analyze_url
from ..services.web_checker import UnsafeTargetError, check_headers

router = APIRouter(prefix="/api/v1")

STAFF = (Role.ADMIN, Role.SECURITY_ANALYST)
MAX_LOG_BYTES = 2_000_000


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _register_failed_login(db: Session, user: User, ip: str | None, reason: str) -> None:
    # Increment in SQL so concurrent guesses cannot overwrite each other and slip past the lockout.
    db.execute(update(User).where(User.id == user.id).values(failed_logins=User.failed_logins + 1))
    db.commit()
    db.refresh(user)
    locked = user.failed_logins >= settings.max_failed_logins
    if locked:
        user.locked_until = datetime.now(UTC) + timedelta(minutes=settings.lockout_minutes)
        db.commit()
    audit(db, user.id, "LOGIN_FAILED", reason, "FAILURE", ip)
    if locked:
        audit(db, user.id, "ACCOUNT_LOCKED", "auth", "SUCCESS", ip)


@router.get("/health")
def health():
    return {"status": "ok", "service": "cybershield"}


@router.post("/auth/register", status_code=201)
def register(data: RegisterIn, request: Request, db: Session = Depends(get_db)):
    errors = validate_password_policy(data.password)
    if errors:
        raise HTTPException(400, errors)
    if db.scalar(select(User).where(User.email == data.email.lower())):
        raise HTTPException(409, "Email already registered")
    user = User(email=data.email.lower(), password_hash=hash_password(data.password), role=Role.USER.value)
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # Lost a race with a concurrent registration of the same email.
        db.rollback()
        raise HTTPException(409, "Email already registered") from None
    db.refresh(user)
    audit(db, user.id, "USER_REGISTERED", "auth", "SUCCESS", _ip(request))
    return {"id": user.id, "email": user.email, "role": user.role}


@router.post("/auth/login")
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = _ip(request)
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user:
        burn_password_check(data.password)
        audit(db, None, "LOGIN_FAILED", "unknown-user", "FAILURE", ip)
        raise HTTPException(401, "Invalid credentials")
    if user.locked_until:
        if _as_aware(user.locked_until) > datetime.now(UTC):
            audit(db, user.id, "LOGIN_BLOCKED", "account-locked", "FAILURE", ip)
            raise HTTPException(423, "Account temporarily locked")
        # The lock has expired: start counting from zero so a single typo does not re-lock the account.
        user.failed_logins = 0
        user.locked_until = None
        db.commit()
    if not verify_password(data.password, user.password_hash):
        _register_failed_login(db, user, ip, "bad-password")
        raise HTTPException(401, "Invalid credentials")
    if user.mfa_enabled and (not data.otp or not verify_totp(user.mfa_secret, data.otp, user.id)):
        _register_failed_login(db, user, ip, "bad-otp")
        raise HTTPException(401, "MFA verification required")
    user.failed_logins = 0
    user.locked_until = None
    db.commit()
    audit(db, user.id, "USER_LOGIN", "auth", "SUCCESS", ip)
    return {"access_token": create_token(user), "token_type": "bearer", "role": user.role}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "role": user.role, "mfa_enabled": user.mfa_enabled}


@router.post("/auth/password/change")
def change_password(
    data: PasswordChangeIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(data.current_password, user.password_hash):
        # Counts toward lockout so a stolen access token cannot be used to guess the current password.
        _register_failed_login(db, user, _ip(request), "bad-current-password")
        raise HTTPException(401, "Current password is incorrect")
    errors = validate_password_policy(data.new_password)
    if data.new_password == data.current_password:
        errors.append("New password must differ from the current password.")
    if errors:
        raise HTTPException(400, errors)
    user.password_hash = hash_password(data.new_password)
    db.commit()
    audit(db, user.id, "PASSWORD_CHANGE", "auth", "SUCCESS", _ip(request))
    return {"status": "password updated"}


@router.post("/auth/mfa/setup")
def mfa_setup(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        # Prevents a stolen access token from silently replacing an active second factor.
        raise HTTPException(409, "MFA is already enabled.")
    secret = new_totp_secret()
    user.mfa_secret = secret
    db.commit()
    audit(db, user.id, "MFA_SETUP", "auth", "SUCCESS", _ip(request))
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="CyberShield")
    return {"secret": secret, "otpauth_uri": uri, "message": "Store the secret securely; it is not logged."}


@router.post("/auth/mfa/enable")
def mfa_enable(
    data: MFACodeIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    if not user.mfa_secret or not verify_totp(user.mfa_secret, data.code, user.id):
        raise HTTPException(400, "Invalid TOTP code")
    user.mfa_enabled = True
    db.commit()
    audit(db, user.id, "MFA_ENABLED", "auth", "SUCCESS", _ip(request))
    return {"enabled": True}


def _dashboard_metrics(db: Session) -> dict:
    def alert_count(severity: str) -> int:
        stmt = select(func.count(Alert.id)).where(
            Alert.severity == severity, Alert.status.notin_(["RESOLVED", "FALSE_POSITIVE"])
        )
        return db.scalar(stmt) or 0

    critical, high, medium = alert_count("CRITICAL"), alert_count("HIGH"), alert_count("MEDIUM")
    incidents = db.scalar(select(func.count(Incident.id)).where(Incident.status != "CLOSED")) or 0
    vulns = db.scalar(select(func.count(Vulnerability.id))) or 0
    score = max(0, 100 - (critical * 15 + high * 7 + medium * 3))
    return {
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "open_incidents": incidents,
        "vulnerabilities": vulns,
        "security_score": score,
    }


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _dashboard_metrics(db)


@router.post("/tools/password/analyze")
def password_tool(data: PasswordAnalyzeIn):
    return analyze_password(data.password)


@router.get("/tools/network/info")
def net_info(user: User = Depends(require_roles(*STAFF))):
    return network_info()


@router.post("/tools/network/scan")
async def net_scan(
    data: PortScanIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    if data.start_port > data.end_port:
        raise HTTPException(400, "Invalid port range")
    try:
        ports = await scan_ports(data.target, data.start_port, data.end_port)
    except ValueError as e:
        audit(db, user.id, "PORT_SCAN_BLOCKED", data.target[:250], "DENIED", _ip(request))
        raise HTTPException(400, str(e)) from None
    audit(db, user.id, "PORT_SCAN", data.target, "SUCCESS", _ip(request))
    return {"target": data.target, "ports": ports}


@router.get("/tools/dns/{domain}")
def dns(domain: str, user: User = Depends(current_user)):
    if not is_valid_domain(domain):
        raise HTTPException(400, "Invalid domain")
    return dns_lookup(domain)


@router.post("/tools/url/analyze")
def url_tool(data: URLAnalyzeIn, user: User = Depends(current_user)):
    return analyze_url(data.url)


@router.post("/tools/web/headers")
async def headers(
    data: URLAnalyzeIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    try:
        result = await check_headers(data.url)
    except UnsafeTargetError as e:
        audit(db, user.id, "WEB_HEADER_CHECK_BLOCKED", data.url[:250], "DENIED", _ip(request))
        raise HTTPException(400, str(e)) from None
    except Exception as e:
        raise HTTPException(400, f"Unable to safely inspect URL: {type(e).__name__}") from None
    audit(db, user.id, "WEB_HEADER_CHECK", result["url"][:250], "SUCCESS", _ip(request))
    return result


@router.post("/tools/logs/analyze")
async def logs(
    request: Request,
    file: UploadFile = File(...),
    save_alerts: bool = False,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    if file.size and file.size > MAX_LOG_BYTES:
        raise HTTPException(413, "Log file too large")
    raw = await file.read(MAX_LOG_BYTES + 1)
    if len(raw) > MAX_LOG_BYTES:
        raise HTTPException(413, "Log file too large")
    # CPU-bound: keep it off the event loop so one upload cannot stall every other request.
    result = await run_in_threadpool(analyze_lines, raw.decode("utf-8", errors="replace").splitlines())
    audit(
        db,
        user.id,
        "LOG_ANALYZED",
        f"lines={result['lines_analyzed']} alerts={len(result['alerts'])} saved={save_alerts}",
        "SUCCESS",
        _ip(request),
    )
    if save_alerts:
        for a in result["alerts"]:
            db.add(
                Alert(
                    alert_type=a["type"],
                    severity=a["severity"],
                    source=a["source"],
                    description=a["description"],
                    evidence=a["evidence"],
                )
            )
        db.commit()
    return result


@router.get("/alerts")
def alerts(user: User = Depends(require_roles(*STAFF)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Alert).order_by(Alert.id.desc()).limit(100))
    return [
        {
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "status": a.status,
            "source": a.source,
            "description": a.description,
            "evidence": a.evidence,
            "assigned_analyst_id": a.assigned_analyst_id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]


def _validate_analyst(db: Session, analyst_id: int | None) -> None:
    if analyst_id is None:
        return
    analyst = db.get(User, analyst_id)
    if not analyst or analyst.role not in {r.value for r in STAFF}:
        raise HTTPException(400, "assigned_analyst_id must reference an existing analyst or admin")


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    data: AlertUpdateIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    _validate_analyst(db, data.assigned_analyst_id)
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(alert, k, v)
    db.commit()
    audit(db, user.id, "ALERT_UPDATED", str(alert_id), "SUCCESS", _ip(request))
    return {"status": "updated"}


@router.get("/incidents")
def incidents(user: User = Depends(require_roles(*STAFF)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Incident).order_by(Incident.id.desc()).limit(100))
    return [
        {
            "id": i.id,
            "title": i.title,
            "severity": i.severity,
            "category": i.category,
            "status": i.status,
            "asset": i.affected_asset,
            "description": i.description,
            "resolution": i.resolution,
            "assigned_analyst_id": i.assigned_analyst_id,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in rows
    ]


@router.post("/incidents", status_code=201)
def create_incident(
    data: IncidentIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    inc = Incident(**data.model_dump())
    db.add(inc)
    db.commit()
    db.refresh(inc)
    audit(db, user.id, "INCIDENT_CREATED", str(inc.id), "SUCCESS", _ip(request))
    return {"id": inc.id}


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    data: IncidentUpdateIn,
    request: Request,
    user: User = Depends(require_roles(*STAFF)),
    db: Session = Depends(get_db),
):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    _validate_analyst(db, data.assigned_analyst_id)
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(inc, k, v)
    db.commit()
    audit(db, user.id, "INCIDENT_UPDATED", str(incident_id), "SUCCESS", _ip(request))
    return {"status": "updated"}


@router.get("/vulnerabilities")
def vulnerabilities(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "description": v.description,
            "recommendation": v.recommendation,
            "cve_id": v.cve_id,
            "cvss": v.cvss,
        }
        for v in db.scalars(select(Vulnerability))
    ]


@router.get("/audit-logs")
def audit_logs(
    limit: int = 100, user: User = Depends(require_roles(Role.ADMIN)), db: Session = Depends(get_db)
):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 500))))
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "action": r.action,
            "resource": r.resource,
            "result": r.result,
            "ip": r.ip_address,
            "at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/reports/security.pdf")
def report(request: Request, user: User = Depends(require_roles(*STAFF)), db: Session = Depends(get_db)):
    m = _dashboard_metrics(db)
    summary = {
        "Executive Summary": "CyberShield defensive assessment",
        "Security Score": m["security_score"],
        "Open Alerts (critical / high / medium)": (
            f"{m['critical_alerts']} / {m['high_alerts']} / {m['medium_alerts']}"
        ),
        "Open Vulnerabilities": m["vulnerabilities"],
        "Open Incidents": m["open_incidents"],
        "Recommendations": "Review high-risk findings, enable MFA and maintain least privilege.",
    }
    audit(db, user.id, "REPORT_GENERATED", "security.pdf", "SUCCESS", _ip(request))
    return Response(
        content=security_report(summary),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=cybershield-security-assessment.pdf"},
    )
