"""API keys for the /v2 machine API (admin-managed).

A key looks like `argus_<prefix>_<secret>`: the prefix is stored in clear so a
key can be recognised in lists and logs, and only the SHA-256 of the whole key
is stored. Keys carry 256 bits of randomness, so a plain hash (not a slow
password hash) is enough and lets every request look its key up by index.
"""

import hashlib
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey
from app.schemas.api_key import ApiKeyCreate
from app.services.audit import Actor, record_audit
from app.services.errors import ConflictError, NotFoundError

KEY_PREFIX = "argus_"
RATE_KEY = "sentinel:apirate:"
# last_used_at is a hint for admins, so it is written at most once a minute per key.
LAST_USED_RESOLUTION = timedelta(minutes=1)


def new_key() -> tuple[str, str]:
    """(full key, prefix)."""
    prefix = secrets.token_hex(4)
    return f"{KEY_PREFIX}{prefix}_{secrets.token_urlsafe(32)}", prefix


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _snapshot(key: ApiKey) -> dict[str, Any]:
    return {"name": key.name, "prefix": key.prefix, "scopes": key.scopes}


async def list_keys(session: AsyncSession, limit: int, offset: int) -> tuple[list[ApiKey], int]:
    total = await session.scalar(select(func.count()).select_from(ApiKey))
    keys = await session.scalars(select(ApiKey).order_by(ApiKey.id).limit(limit).offset(offset))
    return list(keys), total or 0


async def create_key(session: AsyncSession, data: ApiKeyCreate, actor: Actor) -> tuple[ApiKey, str]:
    key, prefix = new_key()
    api_key = ApiKey(
        name=data.name,
        prefix=prefix,
        key_hash=hash_key(key),
        scopes=sorted({scope.value for scope in data.scopes}),
        created_by_id=actor.user_id,
    )
    session.add(api_key)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("An API key with this name already exists") from exc
    record_audit(
        session,
        actor,
        "api_key.created",
        entity_type="api_key",
        entity_id=api_key.id,
        after=_snapshot(api_key),
    )
    await session.commit()
    return api_key, key


async def revoke_key(session: AsyncSession, key_id: int, actor: Actor) -> ApiKey:
    api_key = await session.get(ApiKey, key_id)
    if api_key is None:
        raise NotFoundError("API key not found")
    if api_key.revoked_at is None:
        api_key.revoked_at = datetime.now(UTC)
        record_audit(
            session,
            actor,
            "api_key.revoked",
            entity_type="api_key",
            entity_id=api_key.id,
            before=_snapshot(api_key),
        )
        await session.commit()
    return api_key


async def authenticate(session: AsyncSession, key: str) -> ApiKey | None:
    """The active key matching `key`, or None."""
    if not key.startswith(KEY_PREFIX) or len(key) > 128:
        return None
    api_key = await session.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(key)))
    if api_key is None or api_key.revoked_at is not None:
        return None
    now = datetime.now(UTC)
    if api_key.last_used_at is None or now - api_key.last_used_at >= LAST_USED_RESOLUTION:
        await session.execute(
            update(ApiKey).where(ApiKey.id == api_key.id).values(last_used_at=now)
        )
        await session.commit()
    return api_key


async def within_rate(redis: Redis, key_id: int, limit: int) -> bool:
    """Fixed one-minute window per key. Fails open if Redis is unavailable: the
    database-backed key check still applies, and the reverse proxy is the
    outer limit."""
    window = int(time.time() // 60)
    name = f"{RATE_KEY}{key_id}:{window}"
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr(name)
            pipe.expire(name, 120)
            count, _ = await pipe.execute()
    except RedisError:
        return True
    return int(count) <= limit
