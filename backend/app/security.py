import hashlib
import hmac
import threading
import time
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User

ph = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Verified against when the account does not exist, so response time does not reveal valid emails.
_DUMMY_HASH = ph.hash("cybershield-dummy-password")


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_password_check(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def validate_password_policy(password: str) -> list[str]:
    errors = []
    if len(password) < 12:
        errors.append("Minimum length is 12 characters.")
    if not any(c.isupper() for c in password):
        errors.append("Must contain an uppercase letter.")
    if not any(c.islower() for c in password):
        errors.append("Must contain a lowercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Must contain a number.")
    if not any(not c.isalnum() for c in password):
        errors.append("Must contain a special character.")
    return errors


def credential_fingerprint(user: User) -> str:
    """Keyed digest of the current password hash; tokens minted before a password change stop matching."""
    mac = hmac.new(settings.secret_key.encode(), user.password_hash.encode(), hashlib.sha256)
    return mac.hexdigest()[:16]


def create_token(user: User) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "pv": credential_fingerprint(user),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=["HS256"], options={"require": ["exp", "sub"]}
        )
        user = db.get(User, int(payload["sub"]))
        if user and not hmac.compare_digest(str(payload.get("pv", "")), credential_fingerprint(user)):
            user = None
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(*roles: str):
    allowed = {getattr(r, "value", r) for r in roles}

    def dependency(user: User = Depends(current_user)):
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return dependency


def new_totp_secret() -> str:
    return pyotp.random_base32()


TOTP_STEP_SECONDS = 30
_totp_lock = threading.Lock()
_last_totp_step: dict[int, int] = {}


def verify_totp(secret: str, code: str, user_id: int | None = None) -> bool:
    """Verify a TOTP code within +/-1 step. With `user_id`, a step (or any earlier one) is single-use.

    Replay state is per process (like the rate limiter); use a shared store when running several workers.
    """
    code = code.strip()
    totp = pyotp.TOTP(secret, interval=TOTP_STEP_SECONDS)
    current = int(time.time()) // TOTP_STEP_SECONDS
    with _totp_lock:
        last = _last_totp_step.get(user_id, -1) if user_id is not None else -1
        for step in (current - 1, current, current + 1):
            if step > last and hmac.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code):
                if user_id is not None:
                    _last_totp_step[user_id] = step
                return True
    return False
