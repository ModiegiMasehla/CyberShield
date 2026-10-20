import logging

from ..models import AuditLog

logger = logging.getLogger("cybershield.audit")


def audit(db, user_id, action, resource, result, ip=None):
    """Persist an audit row and mirror it to the application log (never include secrets in `resource`)."""
    db.add(AuditLog(user_id=user_id, action=action, resource=resource[:255], result=result, ip_address=ip))
    db.commit()
    logger.info("audit action=%s result=%s user_id=%s ip=%s", action, result, user_id, ip)
