"""Password hashing, access tokens (JWT) and refresh tokens."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import get_settings, jwt_signing_key

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "argus"
JWT_AUDIENCE = "argus-api"

password_hasher = PasswordHash((Argon2Hasher(),))


class InvalidTokenError(Exception):
    pass


@dataclass(frozen=True)
class AccessToken:
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class AccessClaims:
    user_id: int
    token_version: int
    expires_at: datetime


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


@cache
def _dummy_hash() -> str:
    return password_hasher.hash(secrets.token_urlsafe(16))


def verify_password(password: str, password_hash: str | None) -> tuple[bool, str | None]:
    """Return (valid, upgraded_hash); upgraded_hash is set when hash parameters changed.

    For an unknown user (no hash) a dummy hash is still verified, so response
    timing does not reveal whether the username exists.
    """
    if password_hash is None:
        password_hasher.verify(password, _dummy_hash())
        return False, None
    return password_hasher.verify_and_update(password, password_hash)


def create_access_token(user_id: int, token_version: int) -> AccessToken:
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=get_settings().access_token_minutes)
    claims = {
        "sub": str(user_id),
        "ver": token_version,
        "type": "access",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(claims, jwt_signing_key(), algorithm=JWT_ALGORITHM)
    return AccessToken(token=token, expires_at=expires_at)


def decode_access_token(token: str) -> AccessClaims:
    try:
        claims = jwt.decode(
            token,
            jwt_signing_key(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["sub", "ver", "type", "iat", "exp"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
    if claims["type"] != "access":
        raise InvalidTokenError("not an access token")
    try:
        return AccessClaims(
            user_id=int(claims["sub"]),
            token_version=int(claims["ver"]),
            expires_at=datetime.fromtimestamp(claims["exp"], UTC),
        )
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("malformed claims") from exc


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_refresh_token() -> tuple[str, str]:
    """Return (token, digest). Only the SHA-256 digest is stored server-side."""
    token = secrets.token_urlsafe(32)
    return token, hash_refresh_token(token)
