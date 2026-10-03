"""Login, token refresh/rotation, logout and password changes."""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security import (
    AccessToken,
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    verify_password,
)
from app.models import RefreshToken, User
from app.services.audit import Actor, ClientInfo, record_audit

logger = logging.getLogger(__name__)

# Passwords are capped at this length when set, so longer input can never
# match; rejecting it before hashing stops oversized inputs costing CPU.
MAX_PASSWORD_LENGTH = 128
GENERIC_LOGIN_ERROR = "Incorrect username or password"
GENERIC_REFRESH_ERROR = "Invalid refresh token"


class AuthError(Exception):
    """Authentication failed. The message is safe to return to clients."""


class LoginThrottled(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"retry after {retry_after}s")
        self.retry_after = retry_after


@dataclass(frozen=True)
class IssuedTokens:
    access: AccessToken
    refresh_token: str
    refresh_expires_at: datetime


class LoginThrottle:
    """Fixed-window counters of failed logins per username and per client IP.

    Fails open: if Redis is unavailable, logins still work (argon2 keeps
    guessing expensive) and a warning is logged.
    """

    def __init__(self, redis: Redis, settings: Settings) -> None:
        self.redis = redis
        self.window_s = settings.login_window_minutes * 60
        self.limits = {
            "user": settings.login_max_failures_per_user,
            "ip": settings.login_max_failures_per_ip,
        }

    @staticmethod
    def _keys(username: str, ip: str | None) -> dict[str, str]:
        return {
            "user": f"sentinel:login-failures:user:{username}",
            "ip": f"sentinel:login-failures:ip:{ip or 'unknown'}",
        }

    async def retry_after(self, username: str, ip: str | None) -> int | None:
        keys = self._keys(username, ip)
        try:
            counts = await self.redis.mget(list(keys.values()))
            for (scope, key), count in zip(keys.items(), counts, strict=True):
                if count is not None and int(count) >= self.limits[scope]:
                    return max(await self.redis.ttl(key), 1)
        except RedisError:
            logger.warning("Login throttle unavailable; allowing attempt", exc_info=True)
        return None

    async def record_failure(self, username: str, ip: str | None) -> list[str]:
        """Count a failure; return the scopes that just reached their limit."""
        keys = self._keys(username, ip)
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                for key in keys.values():
                    pipe.incr(key)
                    pipe.expire(key, self.window_s, nx=True)
                results = await pipe.execute()
        except RedisError:
            logger.warning("Login throttle unavailable; failure not counted", exc_info=True)
            return []
        counts = dict(zip(keys, results[0::2], strict=True))
        return [scope for scope, count in counts.items() if count == self.limits[scope]]

    async def reset(self, username: str) -> None:
        try:
            await self.redis.delete(self._keys(username, None)["user"])
        except RedisError:
            logger.warning("Login throttle unavailable; counter not reset", exc_info=True)


async def _issue_tokens(session: AsyncSession, user: User, family_id: uuid.UUID) -> IssuedTokens:
    token, digest = new_refresh_token()
    expires_at = datetime.now(UTC) + timedelta(days=get_settings().refresh_token_days)
    session.add(
        RefreshToken(user_id=user.id, token_hash=digest, family_id=family_id, expires_at=expires_at)
    )
    return IssuedTokens(
        access=create_access_token(user.id, user.token_version),
        refresh_token=token,
        refresh_expires_at=expires_at,
    )


async def end_all_sessions(session: AsyncSession, user: User) -> None:
    """Invalidate every access token (version bump) and refresh token of a user."""
    user.token_version += 1
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


async def login(
    session: AsyncSession,
    throttle: LoginThrottle,
    username: str,
    password: str,
    client: ClientInfo,
) -> IssuedTokens:
    username = username.strip().lower()[:64]
    retry_after = await throttle.retry_after(username, client.ip)
    if retry_after is not None:
        logger.warning("Throttled login attempt for %r from %s", username, client.ip)
        raise LoginThrottled(retry_after)

    user = await session.scalar(select(User).where(User.username == username))
    if len(password) > MAX_PASSWORD_LENGTH:
        valid, upgraded_hash = False, None
    else:
        valid, upgraded_hash = verify_password(password, user.password_hash if user else None)

    if user is None or not valid or not user.is_active:
        anonymous = Actor(user_id=None, username="anonymous", client=client)
        reason = "inactive" if user is not None and valid else "bad_credentials"
        record_audit(
            session,
            anonymous,
            "auth.login_failed",
            entity_type="user",
            entity_id=user.id if user else None,
            after={"username": username, "reason": reason},
        )
        for scope in await throttle.record_failure(username, client.ip):
            record_audit(
                session,
                anonymous,
                "auth.locked",
                after={"username": username, "ip": client.ip, "scope": scope},
            )
        await session.commit()
        raise AuthError(GENERIC_LOGIN_ERROR)

    if upgraded_hash is not None:
        user.password_hash = upgraded_hash
    user.last_login_at = datetime.now(UTC)
    await throttle.reset(username)
    tokens = await _issue_tokens(session, user, family_id=uuid.uuid4())
    actor = Actor(user_id=user.id, username=user.username, client=client)
    record_audit(session, actor, "auth.login", entity_type="user", entity_id=user.id)
    await session.commit()
    return tokens


async def refresh(session: AsyncSession, presented: str, client: ClientInfo) -> IssuedTokens:
    """Rotate a refresh token. Presenting an already-rotated token ends the session family."""
    record = await session.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(presented))
        .with_for_update()
    )
    if record is None:
        raise AuthError(GENERIC_REFRESH_ERROR)
    user = await session.get(User, record.user_id)
    if user is None:
        raise AuthError(GENERIC_REFRESH_ERROR)
    now = datetime.now(UTC)

    if record.revoked_at is not None:
        # A rotated token was replayed while its family is still live: treat it
        # as stolen and end the family, including access tokens issued from it.
        # (A family that is already fully revoked has nothing left to protect.)
        revoked = await session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == record.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        if revoked.rowcount == 0:
            raise AuthError(GENERIC_REFRESH_ERROR)
        user.token_version += 1
        record_audit(
            session,
            Actor(user_id=user.id, username=user.username, client=client),
            "auth.refresh_reuse_detected",
            entity_type="user",
            entity_id=user.id,
            after={"family_id": str(record.family_id)},
        )
        await session.commit()
        raise AuthError(GENERIC_REFRESH_ERROR)

    if record.expires_at <= now or not user.is_active:
        raise AuthError(GENERIC_REFRESH_ERROR)

    record.revoked_at = now
    tokens = await _issue_tokens(session, user, family_id=record.family_id)
    await session.commit()
    return tokens


async def logout(session: AsyncSession, presented: str, client: ClientInfo) -> None:
    record = await session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_refresh_token(presented),
            RefreshToken.revoked_at.is_(None),
        )
    )
    if record is None:
        return
    record.revoked_at = datetime.now(UTC)
    user = await session.get(User, record.user_id)
    if user is not None:
        actor = Actor(user_id=user.id, username=user.username, client=client)
        record_audit(session, actor, "auth.logout", entity_type="user", entity_id=user.id)
    await session.commit()


async def change_password(
    session: AsyncSession, user: User, current: str, new: str, actor: Actor
) -> None:
    if not verify_password(current, user.password_hash)[0]:
        raise AuthError("Current password is incorrect")
    if verify_password(new, user.password_hash)[0]:
        raise AuthError("New password must differ from the current one")
    user.password_hash = hash_password(new)
    await end_all_sessions(session, user)
    record_audit(session, actor, "auth.password_changed", entity_type="user", entity_id=user.id)
    await session.commit()
