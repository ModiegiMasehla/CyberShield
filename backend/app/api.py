from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import Response
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, Alert, Incident, Vulnerability, AuditLog, Role
from ..schemas import *
from ..security import *
from ..services.password_analyzer import analyze_password
from ..services.network import network_info, scan_ports
from ..services.dns_analyzer import lookup as dns_lookup
from ..services.url_analyzer import analyze_url
from ..services.web_checker import check_headers
from ..services.log_analyzer import analyze_lines
from ..services.reports import security_report
from ..services.audit import audit

router=APIRouter(prefix="/api/v1")

@router.get("/health")
def health(): return {"status":"ok","service":"cybershield"}

@router.post("/auth/register")
def register(data:RegisterIn, db:Session=Depends(get_db)):
    if db.scalar(select(User).where(User.email==data.email.lower())): raise HTTPException(409,"Email already registered")
    errors=validate_password_policy(data.password)
    if errors: raise HTTPException(400, errors)
    user=User(email=data.email.lower(),password_hash=hash_password(data.password),role=Role.USER.value)
    db.add(user); db.commit(); db.refresh(user)
    return {"id":user.id,"email":user.email,"role":user.role}

@router.post("/auth/login")
def login(data:LoginIn, db:Session=Depends(get_db)):
    user=db.scalar(select(User).where(User.email==data.email.lower()))
    if not user or not verify_password(data.password,user.password_hash):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= 5: user.locked_until=datetime.now(timezone.utc)+timedelta(minutes=15)
            db.commit()
        raise HTTPException(401,"Invalid credentials")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(423,"Account temporarily locked")
    if user.mfa_enabled:
        if not data.otp or not verify_totp(user.mfa_secret,data.otp):
            raise HTTPException(401,"MFA verification required")
    user.failed_logins=0; user.locked_until=None; db.commit()
    audit(db,user.id,"USER_LOGIN","auth","SUCCESS")
    return {"access_token":create_token(user),"token_type":"bearer","role":user.role}

@router.post("/auth/mfa/setup")
def mfa_setup(user:User=Depends(current_user), db:Session=Depends(get_db)):
    secret=new_totp_secret(); user.mfa_secret=secret; db.commit()
    uri=__import__("pyotp").TOTP(secret).provisioning_uri(name=user.email,issuer_name="CyberShield")
    return {"secret":secret,"otpauth_uri":uri,"message":"Store the secret securely; it is not logged."}

@router.post("/auth/mfa/enable")
def mfa_enable(code:str, user:User=Depends(current_user), db:Session=Depends(get_db)):
    if not user.mfa_secret or not verify_totp(user.mfa_secret,code): raise HTTPException(400,"Invalid TOTP code")
    user.mfa_enabled=True; db.commit(); audit(db,user.id,"MFA_ENABLED","auth","SUCCESS")
    return {"enabled":True}

@router.get("/dashboard")
def dashboard(user:User=Depends(current_user),db:Session=Depends(get_db)):
    critical=db.scalar(select(func.count(Alert.id)).where(Alert.severity=="CRITICAL",Alert.status!="RESOLVED")) or 0
    high=db.scalar(select(func.count(Alert.id)).where(Alert.severity=="HIGH",Alert.status!="RESOLVED")) or 0
    medium=db.scalar(select(func.count(Alert.id)).where(Alert.severity=="MEDIUM",Alert.status!="RESOLVED")) or 0
    incidents=db.scalar(select(func.count(Incident.id)).where(Incident.status!="CLOSED")) or 0
    vulns=db.scalar(select(func.count(Vulnerability.id))) or 0
    score=max(0,100-(critical*15+high*7+medium*3))
    return {"critical_alerts":critical,"high_alerts":high,"medium_alerts":medium,"open_incidents":incidents,"vulnerabilities":vulns,"security_score":score}

@router.post("/tools/password/analyze")
def password_tool(data:dict):
    password=data.get("password","")
    return analyze_password(password)

@router.get("/tools/network/info")
def net_info(user=Depends(current_user)): return network_info()

@router.post("/tools/network/scan")
async def net_scan(data:PortScanIn,user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST))):
    if data.start_port>data.end_port: raise HTTPException(400,"Invalid port range")
    return {"target":data.target,"ports":await scan_ports(data.target,data.start_port,data.end_port)}

@router.get("/tools/dns/{domain}")
def dns(domain:str,user=Depends(current_user)):
    if len(domain)>253: raise HTTPException(400,"Invalid domain")
    return dns_lookup(domain)

@router.post("/tools/url/analyze")
def url_tool(data:URLAnalyzeIn,user=Depends(current_user)): return analyze_url(data.url)

@router.post("/tools/web/headers")
async def headers(data:URLAnalyzeIn,user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST))):
    try: return await check_headers(data.url)
    except Exception as e: raise HTTPException(400,f"Unable to safely inspect URL: {type(e).__name__}")

@router.post("/tools/logs/analyze")
async def logs(file:UploadFile=File(...),user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST))):
    if file.size and file.size>2_000_000: raise HTTPException(413,"Log file too large")
    raw=await file.read(2_000_001)
    if len(raw)>2_000_000: raise HTTPException(413,"Log file too large")
    return analyze_lines(raw.decode("utf-8",errors="replace").splitlines())

@router.get("/alerts")
def alerts(user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST)),db:Session=Depends(get_db)):
    return [{"id":a.id,"type":a.alert_type,"severity":a.severity,"status":a.status,"source":a.source,"description":a.description} for a in db.scalars(select(Alert).order_by(Alert.id.desc()).limit(100))]

@router.get("/incidents")
def incidents(user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST)),db:Session=Depends(get_db)):
    return [{"id":i.id,"title":i.title,"severity":i.severity,"category":i.category,"status":i.status,"asset":i.affected_asset} for i in db.scalars(select(Incident).order_by(Incident.id.desc()).limit(100))]

@router.post("/incidents")
def create_incident(data:IncidentIn,user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST)),db:Session=Depends(get_db)):
    inc=Incident(**data.model_dump()); db.add(inc); db.commit(); db.refresh(inc); audit(db,user.id,"INCIDENT_CREATED",str(inc.id),"SUCCESS")
    return {"id":inc.id}

@router.patch("/incidents/{incident_id}")
def update_incident(incident_id:int,data:IncidentUpdateIn,user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST)),db:Session=Depends(get_db)):
    inc=db.get(Incident,incident_id)
    if not inc: raise HTTPException(404,"Incident not found")
    for k,v in data.model_dump(exclude_none=True).items(): setattr(inc,k,v)
    db.commit(); audit(db,user.id,"INCIDENT_UPDATED",str(incident_id),"SUCCESS")
    return {"status":"updated"}

@router.get("/vulnerabilities")
def vulnerabilities(user=Depends(current_user),db:Session=Depends(get_db)):
    return [{"id":v.id,"title":v.title,"severity":v.severity,"description":v.description,"recommendation":v.recommendation,"cve_id":v.cve_id,"cvss":v.cvss} for v in db.scalars(select(Vulnerability))]

@router.get("/reports/security.pdf")
def report(user=Depends(require_roles(Role.ADMIN,Role.SECURITY_ANALYST)),db:Session=Depends(get_db)):
    summary={"Executive Summary":"CyberShield defensive assessment","Security Score":dashboard(user,db)["security_score"],"Open Vulnerabilities":db.scalar(select(func.count(Vulnerability.id))) or 0,"Open Incidents":db.scalar(select(func.count(Incident.id)).where(Incident.status!="CLOSED")) or 0,"Recommendations":"Review high-risk findings, enable MFA and maintain least privilege."}
    return Response(content=security_report(summary),media_type="application/pdf",headers={"Content-Disposition":"attachment; filename=cybershield-security-assessment.pdf"})
