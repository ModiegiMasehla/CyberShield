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


def create_token(user: User) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user.id),
        "role": user.role,
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


def verify_totp(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
