from sqlalchemy import select
from .models import User, Alert, Incident, Vulnerability, Role
from .security import hash_password

def seed(db):
    if not db.scalar(select(User).where(User.email=="admin@cybershield.local")):
        db.add_all([
            User(email="admin@cybershield.local",password_hash=hash_password("CyberShield!Admin123"),role=Role.ADMIN.value),
            User(email="analyst@cybershield.local",password_hash=hash_password("CyberShield!Analyst123"),role=Role.SECURITY_ANALYST.value),
            User(email="user@cybershield.local",password_hash=hash_password("CyberShield!User123"),role=Role.USER.value)
        ])
        db.flush()
    if not db.scalar(select(Alert)):
        db.add_all([
            Alert(alert_type="BRUTE_FORCE",severity="HIGH",source="192.168.56.20",description="37 failed logins in 2 minutes.",evidence="fictional seed event"),
            Alert(alert_type="SUSPICIOUS_ACTIVITY",severity="MEDIUM",source="lab-web",description="Repeated sensitive-path requests.",evidence="fictional seed event")
        ])
    if not db.scalar(select(Incident)):
        db.add(Incident(title="Credential attack investigation",description="Fictional lab incident created for demonstration.",severity="HIGH",category="Credential attack",affected_asset="lab-auth"))
    if not db.scalar(select(Vulnerability)):
        db.add_all([
            Vulnerability(title="Weak password policy",severity="HIGH",description="Demo asset does not enforce a strong password policy.",impact="Credential compromise is easier.",recommendation="Use strong password requirements and MFA."),
            Vulnerability(title="Missing security header",severity="MEDIUM",description="CSP is absent on the lab web service.",impact="Increases browser-side attack surface.",recommendation="Deploy an appropriate Content-Security-Policy.")
        ])
    db.commit()
