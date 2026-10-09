from ..models import AuditLog
def audit(db, user_id, action, resource, result, ip=None):
    db.add(AuditLog(user_id=user_id, action=action, resource=resource, result=result, ip_address=ip))
    db.commit()
