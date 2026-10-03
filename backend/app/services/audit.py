"""Audit trail. Entries are added to the caller's session, so an action and its
audit record are committed (or rolled back) together."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


@dataclass(frozen=True)
class ClientInfo:
    ip: str | None = None
    user_agent: str | None = None


@dataclass(frozen=True)
class Actor:
    user_id: int | None
    username: str
    client: ClientInfo = ClientInfo()


SYSTEM_ACTOR = Actor(user_id=None, username="system")


def _parse_ip(value: str | None) -> IPv4Address | IPv6Address | None:
    if value is None:
        return None
    try:
        return ip_address(value)
    except ValueError:
        return None


def record_audit(
    session: AsyncSession,
    actor: Actor,
    action: str,
    *,
    entity_type: str | None = None,
    entity_id: int | str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditLog(
            actor_id=actor.user_id,
            actor=actor.username[:64],
            action=action,
            entity_type=entity_type,
            entity_id=None if entity_id is None else str(entity_id),
            before=before,
            after=after,
            ip=_parse_ip(actor.client.ip),
            user_agent=actor.client.user_agent,
        )
    )


@dataclass(frozen=True)
class AuditFilters:
    actor: str | None = None
    action: str | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None


async def list_audit(
    session: AsyncSession, filters: AuditFilters, limit: int, offset: int
) -> tuple[list[AuditLog], int]:
    conditions = []
    if filters.actor is not None:
        conditions.append(AuditLog.actor == filters.actor)
    if filters.action is not None:
        conditions.append(AuditLog.action == filters.action)
    if filters.entity_type is not None:
        conditions.append(AuditLog.entity_type == filters.entity_type)
    if filters.entity_id is not None:
        conditions.append(AuditLog.entity_id == filters.entity_id)
    if filters.since is not None:
        conditions.append(AuditLog.ts >= filters.since)
    if filters.until is not None:
        conditions.append(AuditLog.ts <= filters.until)
    total = await session.scalar(select(func.count()).select_from(AuditLog).where(*conditions))
    entries = await session.scalars(
        select(AuditLog).where(*conditions).order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    )
    return list(entries), total or 0
