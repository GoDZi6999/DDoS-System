"""Alert engine: turns detections into alerts and drives the SOC workflow
NEW -> INVESTIGATING -> CONTAINED -> RESOLVED (or FALSE_POSITIVE)."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from sqlalchemy import distinct, func, insert, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AlertNote, AuditLog, NetworkEvent, Prediction, User, alert_events
from app.models.enums import (
    OPEN_ALERT_STATUSES,
    AlertStatus,
    Role,
    Severity,
    severity_for,
)
from app.schemas.alert import AlertDetail, AlertSummary, HistoryEntry, NoteOut
from app.schemas.config import DetectionConfig
from app.schemas.detection import BENIGN_LABEL, Detection
from app.schemas.user import UserRef
from app.services.audit import SYSTEM_ACTOR, Actor, record_audit
from app.services.errors import ConflictError, NotFoundError, UnprocessableError
from app.services.playbook import describe, recommended_action

S = AlertStatus
TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    S.NEW: frozenset({S.INVESTIGATING, S.FALSE_POSITIVE}),
    S.INVESTIGATING: frozenset({S.CONTAINED, S.RESOLVED, S.FALSE_POSITIVE}),
    S.CONTAINED: frozenset({S.INVESTIGATING, S.RESOLVED}),
    # Reopening is allowed and audited like any other transition.
    S.RESOLVED: frozenset({S.INVESTIGATING}),
    S.FALSE_POSITIVE: frozenset({S.INVESTIGATING}),
}
CLOSED_STATUSES = frozenset({S.RESOLVED, S.FALSE_POSITIVE})
SEVERITY_ORDER = list(Severity)


@dataclass(frozen=True)
class AlertFilters:
    statuses: tuple[AlertStatus, ...] = ()
    severities: tuple[Severity, ...] = ()
    attack_type: str | None = None
    ip: IPv4Address | IPv6Address | None = None
    since: datetime | None = None
    until: datetime | None = None
    sort: Literal["last_seen", "risk"] = "last_seen"


@dataclass
class IngestResult:
    event_id: int
    alert: Alert | None = None
    created: bool = False
    escalated: bool = False
    duplicate: bool = False


# --- Reading ------------------------------------------------------------------


async def _users_by_id(session: AsyncSession, ids: Iterable[int | None]) -> dict[int, User]:
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    users = await session.scalars(select(User).where(User.id.in_(wanted)))
    return {user.id: user for user in users}


def _ref(users: dict[int, User], user_id: int | None) -> UserRef | None:
    user = users.get(user_id) if user_id is not None else None
    return UserRef.model_validate(user) if user is not None else None


def _summary(alert: Alert, users: dict[int, User]) -> AlertSummary:
    fields = {
        name: getattr(alert, name) for name in AlertSummary.model_fields if name != "assigned_to"
    }
    return AlertSummary(**fields, assigned_to=_ref(users, alert.assigned_to_id))


async def summarize(session: AsyncSession, alert: Alert) -> AlertSummary:
    return _summary(alert, await _users_by_id(session, [alert.assigned_to_id]))


async def list_alerts(
    session: AsyncSession, filters: AlertFilters, limit: int, offset: int
) -> tuple[list[AlertSummary], int]:
    conditions = []
    if filters.statuses:
        conditions.append(Alert.status.in_(filters.statuses))
    if filters.severities:
        conditions.append(Alert.severity.in_(filters.severities))
    if filters.attack_type is not None:
        conditions.append(Alert.attack_type == filters.attack_type)
    if filters.ip is not None:
        conditions.append(or_(Alert.source_ip == filters.ip, Alert.destination_ip == filters.ip))
    if filters.since is not None:
        conditions.append(Alert.last_seen_at >= filters.since)
    if filters.until is not None:
        conditions.append(Alert.first_seen_at <= filters.until)

    total = await session.scalar(select(func.count()).select_from(Alert).where(*conditions))
    order = (
        (Alert.risk_score.desc(), Alert.last_seen_at.desc())
        if filters.sort == "risk"
        else (Alert.last_seen_at.desc(),)
    )
    alerts = list(
        await session.scalars(
            select(Alert)
            .where(*conditions)
            .order_by(*order, Alert.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    users = await _users_by_id(session, (a.assigned_to_id for a in alerts))
    return [_summary(alert, users) for alert in alerts], total or 0


async def get_alert(session: AsyncSession, alert_id: int) -> Alert:
    alert = await session.get(Alert, alert_id)
    if alert is None:
        raise NotFoundError("Alert not found")
    return alert


async def get_alert_detail(session: AsyncSession, alert_id: int) -> AlertDetail:
    alert = await get_alert(session, alert_id)
    notes = list(
        await session.scalars(
            select(AlertNote)
            .where(AlertNote.alert_id == alert_id)
            .order_by(AlertNote.created_at, AlertNote.id)
        )
    )
    history = await session.scalars(
        select(AuditLog)
        .where(AuditLog.entity_type == "alert", AuditLog.entity_id == str(alert_id))
        .order_by(AuditLog.id)
    )
    unique_sources = await session.scalar(
        select(func.count(distinct(NetworkEvent.src_ip)))
        .select_from(alert_events)
        .join(NetworkEvent, NetworkEvent.id == alert_events.c.event_id)
        .where(alert_events.c.alert_id == alert_id)
    )
    users = await _users_by_id(
        session,
        [alert.assigned_to_id, alert.acknowledged_by_id, *(n.author_id for n in notes)],
    )
    summary = _summary(alert, users)
    return AlertDetail(
        **summary.model_dump(),
        recommended_action=alert.recommended_action,
        explanation=alert.explanation,
        risk_components=alert.risk_components,
        model_version=alert.model_version,
        acknowledged_by=_ref(users, alert.acknowledged_by_id),
        acknowledged_at=alert.acknowledged_at,
        resolved_at=alert.resolved_at,
        unique_sources=unique_sources or 0,
        allowed_transitions=[s for s in AlertStatus if s in TRANSITIONS[alert.status]],
        notes=[
            NoteOut(id=n.id, author=_ref(users, n.author_id), body=n.body, created_at=n.created_at)
            for n in notes
        ],
        history=[
            HistoryEntry(ts=e.ts, actor=e.actor, action=e.action, before=e.before, after=e.after)
            for e in history
        ],
    )


# --- Workflow -----------------------------------------------------------------


async def _lock(session: AsyncSession, alert_id: int) -> Alert:
    alert = await session.get(Alert, alert_id, with_for_update=True, populate_existing=True)
    if alert is None:
        raise NotFoundError("Alert not found")
    return alert


async def _transition(
    session: AsyncSession,
    alert_id: int,
    new_status: AlertStatus,
    actor: Actor,
    action: str,
    note: str | None = None,
) -> Alert:
    alert = await _lock(session, alert_id)
    old_status = alert.status
    if new_status not in TRANSITIONS[old_status]:
        raise ConflictError(f"Cannot move an alert from {old_status} to {new_status}")
    now = datetime.now(UTC)
    alert.status = new_status
    if old_status == S.NEW and alert.acknowledged_at is None:
        alert.acknowledged_at = now
        alert.acknowledged_by_id = actor.user_id
    if new_status in CLOSED_STATUSES:
        alert.resolved_at = now
    elif old_status in CLOSED_STATUSES:
        alert.resolved_at = None
    if note:
        session.add(AlertNote(alert_id=alert.id, author_id=actor.user_id, body=note))
    record_audit(
        session,
        actor,
        action,
        entity_type="alert",
        entity_id=alert.id,
        before={"status": old_status.value},
        after={"status": new_status.value, "note": bool(note)},
    )
    await session.commit()
    return alert


async def change_status(
    session: AsyncSession,
    alert_id: int,
    new_status: AlertStatus,
    actor: Actor,
    note: str | None = None,
) -> Alert:
    return await _transition(session, alert_id, new_status, actor, "alert.status_changed", note)


async def acknowledge(session: AsyncSession, alert_id: int, actor: Actor) -> Alert:
    alert = await get_alert(session, alert_id)
    if alert.status != S.NEW:
        raise ConflictError("Alert is already acknowledged")
    return await _transition(session, alert_id, S.INVESTIGATING, actor, "alert.acknowledged")


async def add_note(session: AsyncSession, alert_id: int, body: str, actor: Actor) -> NoteOut:
    await get_alert(session, alert_id)
    note = AlertNote(alert_id=alert_id, author_id=actor.user_id, body=body)
    session.add(note)
    await session.flush()
    record_audit(
        session,
        actor,
        "alert.note_added",
        entity_type="alert",
        entity_id=alert_id,
        after={"note_id": note.id},
    )
    await session.commit()
    author = UserRef(id=actor.user_id, username=actor.username)
    return NoteOut(id=note.id, author=author, body=note.body, created_at=note.created_at)


async def set_assignee(
    session: AsyncSession, alert_id: int, user_id: int | None, actor: Actor
) -> Alert:
    alert = await _lock(session, alert_id)
    if user_id is not None:
        assignee = await session.get(User, user_id)
        if assignee is None or not assignee.is_active or not assignee.role.includes(Role.ANALYST):
            raise UnprocessableError("Assignee must be an active analyst or admin")
    before = {"assigned_to_id": alert.assigned_to_id}
    alert.assigned_to_id = user_id
    record_audit(
        session,
        actor,
        "alert.assigned",
        entity_type="alert",
        entity_id=alert.id,
        before=before,
        after={"assigned_to_id": user_id},
    )
    await session.commit()
    return alert


# --- Ingestion ----------------------------------------------------------------


async def ingest_detection(
    session: AsyncSession,
    detection: Detection,
    config: DetectionConfig,
    stream_id: str | None = None,
) -> IngestResult:
    """Store one detection and fold it into an alert when it is an attack.

    Detections correlate by (attack type, destination): an open alert for the
    same pair seen within the aggregation window absorbs the detection, so a
    flood raises one alert instead of thousands. The caller commits.
    """
    if stream_id is not None:
        existing = await session.scalar(
            select(NetworkEvent.id).where(NetworkEvent.stream_id == stream_id)
        )
        if existing is not None:
            return IngestResult(event_id=existing, duplicate=True)

    d = detection
    event = NetworkEvent(
        stream_id=stream_id,
        ts=d.ts,
        src_ip=d.src_ip,
        dst_ip=d.dst_ip,
        src_port=d.src_port,
        dst_port=d.dst_port,
        protocol=d.protocol,
        packet_count=d.packet_count,
        byte_count=d.byte_count,
        duration=d.duration,
        packets_per_sec=d.packets_per_sec,
        bytes_per_sec=d.bytes_per_sec,
        features=d.features,
        source=d.source,
    )
    session.add(event)
    await session.flush()
    severity = severity_for(d.risk_score)
    explanation = [item.model_dump() for item in d.explanation]
    session.add(
        Prediction(
            event_id=event.id,
            model_version=d.model_version,
            label=d.label,
            confidence=d.confidence,
            class_probs=d.class_probs,
            explanation=explanation,
            risk_score=d.risk_score,
            risk_components=d.risk_components,
            severity=severity,
        )
    )
    if d.label == BENIGN_LABEL or d.risk_score < config.alert_min_risk:
        return IngestResult(event_id=event.id)

    # Serialise correlation for this (type, destination) across worker processes.
    lock_key = f"alert:{d.label}:{d.dst_ip}"
    await session.execute(select(func.pg_advisory_xact_lock(func.hashtext(lock_key))))
    window_start = d.ts - timedelta(minutes=config.aggregation_window_minutes)
    alert = await session.scalar(
        select(Alert)
        .where(
            Alert.attack_type == d.label,
            Alert.destination_ip == d.dst_ip,
            Alert.status.in_(OPEN_ALERT_STATUSES),
            Alert.last_seen_at >= window_start,
        )
        .order_by(Alert.last_seen_at.desc())
        .limit(1)
        .with_for_update()
    )

    created = alert is None
    escalated = False
    if alert is None:
        alert = Alert(
            first_seen_at=d.ts,
            last_seen_at=d.ts,
            attack_type=d.label,
            source_ip=d.src_ip,
            destination_ip=d.dst_ip,
            destination_port=d.dst_port,
            protocol=d.protocol,
            confidence=d.confidence,
            risk_score=d.risk_score,
            severity=severity,
            status=S.NEW,
            description=describe(d.label, d.confidence, d.dst_ip, d.dst_port),
            recommended_action=recommended_action(d.label, severity, d.src_ip, d.dst_ip),
            detection_count=1,
            peak_packets_per_sec=d.packets_per_sec,
            peak_bytes_per_sec=d.bytes_per_sec,
            explanation=explanation,
            risk_components=d.risk_components,
            model_version=d.model_version,
        )
        session.add(alert)
        await session.flush()
        record_audit(
            session,
            SYSTEM_ACTOR,
            "alert.created",
            entity_type="alert",
            entity_id=alert.id,
            after={"severity": severity.value, "risk_score": d.risk_score},
        )
    else:
        alert.detection_count += 1
        alert.first_seen_at = min(alert.first_seen_at, d.ts)
        alert.last_seen_at = max(alert.last_seen_at, d.ts)
        alert.peak_packets_per_sec = max(alert.peak_packets_per_sec, d.packets_per_sec)
        alert.peak_bytes_per_sec = max(alert.peak_bytes_per_sec, d.bytes_per_sec)
        alert.confidence = max(alert.confidence, d.confidence)
        if d.risk_score > alert.risk_score:
            # The highest-risk detection drives the alert's score and explanation.
            previous = alert.severity
            escalated = SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(previous)
            alert.risk_score = d.risk_score
            alert.severity = severity
            alert.source_ip = d.src_ip
            alert.explanation = explanation
            alert.risk_components = d.risk_components
            alert.model_version = d.model_version
            alert.recommended_action = recommended_action(d.label, severity, d.src_ip, d.dst_ip)
            if escalated:
                record_audit(
                    session,
                    SYSTEM_ACTOR,
                    "alert.escalated",
                    entity_type="alert",
                    entity_id=alert.id,
                    before={"severity": previous.value},
                    after={"severity": severity.value, "risk_score": d.risk_score},
                )
        alert.description = describe(
            d.label, alert.confidence, alert.destination_ip, alert.destination_port
        )

    await session.execute(insert(alert_events).values(alert_id=alert.id, event_id=event.id))
    return IngestResult(event_id=event.id, alert=alert, created=created, escalated=escalated)
