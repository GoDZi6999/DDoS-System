"""Read access to analysed flows (network events) and their predictions."""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NetworkEvent, Prediction, alert_events
from app.schemas.event import EventDetail, EventSummary
from app.services.errors import NotFoundError


@dataclass(frozen=True)
class EventFilters:
    label: str | None = None
    ip: IPv4Address | IPv6Address | None = None
    since: datetime | None = None
    until: datetime | None = None
    min_risk: int | None = None
    alert_id: int | None = None


def _summary_fields(event: NetworkEvent, prediction: Prediction) -> dict:
    return {
        "id": event.id,
        "ts": event.ts,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "packet_count": event.packet_count,
        "byte_count": event.byte_count,
        "packets_per_sec": event.packets_per_sec,
        "bytes_per_sec": event.bytes_per_sec,
        "source": event.source,
        "label": prediction.label,
        "confidence": prediction.confidence,
        "risk_score": prediction.risk_score,
        "severity": prediction.severity,
    }


def _filtered(stmt: Select, filters: EventFilters) -> Select:
    if filters.label is not None:
        stmt = stmt.where(Prediction.label == filters.label)
    if filters.ip is not None:
        stmt = stmt.where(or_(NetworkEvent.src_ip == filters.ip, NetworkEvent.dst_ip == filters.ip))
    if filters.since is not None:
        stmt = stmt.where(NetworkEvent.ts >= filters.since)
    if filters.until is not None:
        stmt = stmt.where(NetworkEvent.ts <= filters.until)
    if filters.min_risk is not None:
        stmt = stmt.where(Prediction.risk_score >= filters.min_risk)
    if filters.alert_id is not None:
        stmt = stmt.join(alert_events, alert_events.c.event_id == NetworkEvent.id).where(
            alert_events.c.alert_id == filters.alert_id
        )
    return stmt


async def list_events(
    session: AsyncSession, filters: EventFilters, limit: int, offset: int
) -> tuple[list[EventSummary], int]:
    joined = select(NetworkEvent, Prediction).join(
        Prediction, Prediction.event_id == NetworkEvent.id
    )
    count_stmt = _filtered(
        select(func.count())
        .select_from(NetworkEvent)
        .join(Prediction, Prediction.event_id == NetworkEvent.id),
        filters,
    )
    total = await session.scalar(count_stmt) or 0
    rows = await session.execute(
        _filtered(joined, filters)
        .order_by(NetworkEvent.ts.desc(), NetworkEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return [EventSummary(**_summary_fields(event, pred)) for event, pred in rows], total


async def get_event(session: AsyncSession, event_id: int) -> EventDetail:
    row = (
        await session.execute(
            select(NetworkEvent, Prediction)
            .join(Prediction, Prediction.event_id == NetworkEvent.id)
            .where(NetworkEvent.id == event_id)
        )
    ).first()
    if row is None:
        raise NotFoundError("Event not found")
    event, prediction = row
    alert_ids = await session.scalars(
        select(alert_events.c.alert_id).where(alert_events.c.event_id == event_id)
    )
    return EventDetail(
        **_summary_fields(event, prediction),
        duration=event.duration,
        features=event.features,
        class_probs=prediction.class_probs,
        explanation=prediction.explanation,
        risk_components=prediction.risk_components,
        model_version=prediction.model_version,
        alert_ids=sorted(alert_ids),
    )
