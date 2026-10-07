"""Alert notifications: channel management and the delivery outbox.

The alert engine calls enqueue_for_alert in the transaction that creates or
escalates an alert, so a delivery is queued exactly when the alert change
commits. The notifier worker (app.workers.notifier) sends queued deliveries.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Alert, NotificationChannel, NotificationDelivery
from app.models.enums import ChannelKind, DeliveryStatus, NotificationEvent, Severity
from app.schemas.common import Page
from app.schemas.notification import (
    CONFIG_MODELS,
    ChannelCreate,
    ChannelOut,
    ChannelRef,
    ChannelUpdate,
    DeliveryOut,
)
from app.services.audit import Actor, record_audit
from app.services.errors import ConflictError, NotFoundError, UnprocessableError

SEVERITY_ORDER = list(Severity)
RATE_WINDOW = timedelta(hours=1)
RATE_LIMITED = "Channel rate limit reached (max_per_hour)"


# --- message payloads --------------------------------------------------------


def alert_payload(alert: Alert, event: NotificationEvent) -> dict[str, Any]:
    """What a notification says about an alert, frozen at the time it is queued."""
    return {
        "event": event.value,
        "alert": {
            "id": alert.id,
            "severity": alert.severity.value,
            "attack_type": alert.attack_type,
            "description": alert.description,
            "source_ip": str(alert.source_ip),
            "destination_ip": str(alert.destination_ip),
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "risk_score": alert.risk_score,
            "confidence": round(alert.confidence, 4),
            "detection_count": alert.detection_count,
            "first_seen_at": alert.first_seen_at.isoformat(),
            "recommended_action": alert.recommended_action,
        },
        "url": f"{get_settings().dashboard_url.rstrip('/')}/alerts/{alert.id}",
    }


def test_payload(channel: NotificationChannel) -> dict[str, Any]:
    return {
        "event": NotificationEvent.TEST.value,
        "channel": channel.name,
        "url": get_settings().dashboard_url.rstrip("/"),
    }


def title(payload: dict[str, Any]) -> str:
    alert = payload.get("alert")
    if not alert:
        return f"Argus test notification for channel '{payload.get('channel', '?')}'"
    verb = "escalated" if payload["event"] == NotificationEvent.ALERT_ESCALATED else "new alert"
    return f"[{alert['severity']}] {verb}: {alert['description']} (risk {alert['risk_score']})"


# --- outbox ------------------------------------------------------------------


async def _recent_count(session: AsyncSession, channel_id: int, now: datetime) -> int:
    return (
        await session.scalar(
            select(func.count())
            .select_from(NotificationDelivery)
            .where(
                NotificationDelivery.channel_id == channel_id,
                NotificationDelivery.created_at >= now - RATE_WINDOW,
                NotificationDelivery.status != DeliveryStatus.SUPPRESSED,
            )
        )
        or 0
    )


async def _queue(
    session: AsyncSession,
    channel: NotificationChannel,
    *,
    event: NotificationEvent,
    dedupe_key: str,
    payload: dict[str, Any],
    alert_id: int | None = None,
) -> int | None:
    """Insert a delivery unless one with the same key exists. Returns its id."""
    now = datetime.now(UTC)
    limited = await _recent_count(session, channel.id, now) >= channel.max_per_hour
    statement = (
        insert(NotificationDelivery)
        .values(
            channel_id=channel.id,
            alert_id=alert_id,
            event=event,
            dedupe_key=dedupe_key,
            status=DeliveryStatus.SUPPRESSED if limited else DeliveryStatus.PENDING,
            last_error=RATE_LIMITED if limited else None,
            payload=payload,
        )
        .on_conflict_do_nothing(constraint="uq_notification_deliveries_channel_id")
        .returning(NotificationDelivery.id)
    )
    return await session.scalar(statement)


async def enqueue_for_alert(session: AsyncSession, alert: Alert, *, created: bool) -> int:
    """Queue a notification on every enabled channel whose threshold the alert
    meets. Each channel hears about an alert once per severity band, so a
    flood that keeps updating its alert does not send repeated messages.
    Returns the number of deliveries queued."""
    level = SEVERITY_ORDER.index(alert.severity)
    channels = await session.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
    )
    notified = set()
    if not created:
        notified = set(
            await session.scalars(
                select(NotificationDelivery.channel_id).where(
                    NotificationDelivery.alert_id == alert.id,
                    # A rate-limited delivery was never sent: the channel has
                    # not heard about the alert yet.
                    NotificationDelivery.status != DeliveryStatus.SUPPRESSED,
                )
            )
        )
    queued = 0
    for channel in channels:
        if level < SEVERITY_ORDER.index(channel.min_severity):
            continue
        # A channel's first message about an alert reads as a new alert, even
        # when the alert only now crossed the channel's threshold.
        event = (
            NotificationEvent.ALERT_ESCALATED
            if channel.id in notified
            else NotificationEvent.ALERT_CREATED
        )
        delivery_id = await _queue(
            session,
            channel,
            event=event,
            dedupe_key=f"alert:{alert.id}:{alert.severity.value}",
            payload=alert_payload(alert, event),
            alert_id=alert.id,
        )
        queued += delivery_id is not None
    return queued


# --- channels ----------------------------------------------------------------


def _check_url(url: str) -> None:
    """Scheme rule checked when a channel is saved; the worker additionally
    refuses private addresses when it resolves the host before sending."""
    if urlsplit(url).scheme != "https" and not get_settings().notify_allow_private_targets:
        raise UnprocessableError("Webhook URLs must use https")


def _validate_config(
    kind: ChannelKind, raw: dict[str, Any], existing: dict[str, Any] | None = None
) -> dict[str, Any]:
    raw = dict(raw)
    if kind == ChannelKind.WEBHOOK and existing is not None and "secret" not in raw:
        raw["secret"] = existing.get("secret")  # omitted secret: keep the stored one
    try:
        model = CONFIG_MODELS[kind].model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'config'}: {e['msg']}" for e in exc.errors()
        )
        raise UnprocessableError(f"Invalid {kind.value} settings: {problems}") from exc
    config = model.model_dump(mode="json")
    for key in ("webhook_url", "url"):
        if key in config:
            _check_url(config[key])
    return config


def _mask_url(url: str) -> str:
    """Keep scheme and host; hide the path and query, which carry Slack tokens."""
    parts = urlsplit(url)
    path = parts.path
    hidden = f"/…{path[-4:]}" if len(path) > 8 else path
    return urlunsplit((parts.scheme, parts.netloc, hidden, "", ""))


def mask_config(kind: ChannelKind, config: dict[str, Any]) -> dict[str, Any]:
    if kind == ChannelKind.EMAIL:
        return {"recipients": config.get("recipients", [])}
    if kind == ChannelKind.SLACK:
        return {"webhook_url": _mask_url(config.get("webhook_url", ""))}
    return {"url": _mask_url(config.get("url", "")), "secret_set": bool(config.get("secret"))}


def _audit_view(channel: NotificationChannel) -> dict[str, Any]:
    return {
        "name": channel.name,
        "kind": channel.kind.value,
        "enabled": channel.enabled,
        "min_severity": channel.min_severity.value,
        "max_per_hour": channel.max_per_hour,
        "config": mask_config(channel.kind, channel.config),
    }


async def _last_deliveries(
    session: AsyncSession, channel_ids: list[int]
) -> dict[int, NotificationDelivery]:
    if not channel_ids:
        return {}
    rows = await session.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.channel_id.in_(channel_ids))
        .ext(distinct_on(NotificationDelivery.channel_id))
        .order_by(NotificationDelivery.channel_id, NotificationDelivery.created_at.desc())
    )
    return {row.channel_id: row for row in rows}


def _out(channel: NotificationChannel, last: NotificationDelivery | None) -> ChannelOut:
    return ChannelOut(
        id=channel.id,
        name=channel.name,
        kind=channel.kind,
        enabled=channel.enabled,
        min_severity=channel.min_severity,
        max_per_hour=channel.max_per_hour,
        config=mask_config(channel.kind, channel.config),
        created_at=channel.created_at,
        updated_at=channel.updated_at,
        last_delivery_at=last.created_at if last else None,
        last_delivery_status=last.status if last else None,
    )


async def list_channels(session: AsyncSession) -> list[ChannelOut]:
    channels = list(
        await session.scalars(select(NotificationChannel).order_by(NotificationChannel.name))
    )
    last = await _last_deliveries(session, [c.id for c in channels])
    return [_out(c, last.get(c.id)) for c in channels]


async def get_channel(session: AsyncSession, channel_id: int) -> NotificationChannel:
    channel = await session.get(NotificationChannel, channel_id)
    if channel is None:
        raise NotFoundError("Notification channel not found")
    return channel


async def channel_out(session: AsyncSession, channel: NotificationChannel) -> ChannelOut:
    last = await _last_deliveries(session, [channel.id])
    return _out(channel, last.get(channel.id))


async def _name_taken(session: AsyncSession, name: str, exclude_id: int | None = None) -> bool:
    query = select(NotificationChannel.id).where(
        func.lower(NotificationChannel.name) == name.lower()
    )
    if exclude_id is not None:
        query = query.where(NotificationChannel.id != exclude_id)
    return await session.scalar(query) is not None


async def create_channel(
    session: AsyncSession, body: ChannelCreate, actor: Actor
) -> NotificationChannel:
    if await _name_taken(session, body.name):
        raise ConflictError("A channel with this name already exists")
    channel = NotificationChannel(
        name=body.name,
        kind=body.kind,
        enabled=body.enabled,
        min_severity=body.min_severity,
        max_per_hour=body.max_per_hour,
        config=_validate_config(body.kind, body.config),
        created_by_id=actor.user_id,
    )
    session.add(channel)
    await session.flush()
    record_audit(
        session,
        actor,
        "notification.channel_created",
        entity_type="notification_channel",
        entity_id=channel.id,
        after=_audit_view(channel),
    )
    await session.commit()
    await session.refresh(channel)
    return channel


async def update_channel(
    session: AsyncSession, channel_id: int, body: ChannelUpdate, actor: Actor
) -> NotificationChannel:
    channel = await session.get(NotificationChannel, channel_id, with_for_update=True)
    if channel is None:
        raise NotFoundError("Notification channel not found")
    before = _audit_view(channel)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("name") and await _name_taken(session, changes["name"], channel.id):
        raise ConflictError("A channel with this name already exists")
    for field in ("name", "enabled", "min_severity", "max_per_hour"):
        if changes.get(field) is not None:
            setattr(channel, field, changes[field])
    if body.config is not None:
        channel.config = _validate_config(channel.kind, body.config, existing=channel.config)
    after = _audit_view(channel)
    if after != before:
        record_audit(
            session,
            actor,
            "notification.channel_updated",
            entity_type="notification_channel",
            entity_id=channel.id,
            before=before,
            after=after,
        )
    await session.commit()
    await session.refresh(channel)
    return channel


async def send_test(session: AsyncSession, channel_id: int, actor: Actor) -> int:
    channel = await get_channel(session, channel_id)
    delivery_id = await _queue(
        session,
        channel,
        event=NotificationEvent.TEST,
        dedupe_key=f"test:{uuid.uuid4().hex}",
        payload=test_payload(channel),
    )
    record_audit(
        session,
        actor,
        "notification.test_sent",
        entity_type="notification_channel",
        entity_id=channel.id,
    )
    await session.commit()
    assert delivery_id is not None  # noqa: S101 (fresh random key cannot collide)
    return delivery_id


# --- delivery log ------------------------------------------------------------


async def list_deliveries(
    session: AsyncSession,
    *,
    channel_id: int | None,
    alert_id: int | None,
    statuses: list[DeliveryStatus] | None,
    limit: int,
    offset: int,
) -> Page[DeliveryOut]:
    query = select(NotificationDelivery, NotificationChannel).join(
        NotificationChannel, NotificationChannel.id == NotificationDelivery.channel_id
    )
    if channel_id is not None:
        query = query.where(NotificationDelivery.channel_id == channel_id)
    if alert_id is not None:
        query = query.where(NotificationDelivery.alert_id == alert_id)
    if statuses:
        query = query.where(NotificationDelivery.status.in_(statuses))
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = await session.execute(
        query.order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items = [
        DeliveryOut(
            id=d.id,
            channel=ChannelRef(id=c.id, name=c.name, kind=c.kind),
            alert_id=d.alert_id,
            event=d.event,
            status=d.status,
            attempts=d.attempts,
            last_error=d.last_error,
            title=title(d.payload),
            created_at=d.created_at,
            next_attempt_at=d.next_attempt_at,
            sent_at=d.sent_at,
        )
        for d, c in rows
    ]
    return Page(items=items, total=total, limit=limit, offset=offset)
