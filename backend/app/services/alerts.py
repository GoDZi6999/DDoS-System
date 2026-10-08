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
from app.services.notifications import enqueue_for_alert
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


def _new_alert(d: Detection, severity: Severity, explanation: list[dict]) -> Alert:
    return Alert(
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


def _absorb(
    session: AsyncSession,
    alert: Alert,
    d: Detection,
    severity: Severity,
    explanation: list[dict],
) -> bool:
    """Fold a detection into an open alert. Returns True if the alert moved
    to a higher severity band."""
    escalated = False
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
        # The engine explains only a sample of flood flows; keep the current
        # explanation when this detection carries none.
        if explanation:
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
    return escalated


def _event_row(stream_id: str | None, d: Detection) -> dict:
    return {
        "stream_id": stream_id,
        "ts": d.ts,
        # Bulk inserts bypass the ORM's INET conversion; asyncpg takes strings.
        "src_ip": str(d.src_ip),
        "dst_ip": str(d.dst_ip),
        "src_port": d.src_port,
        "dst_port": d.dst_port,
        "protocol": d.protocol,
        "packet_count": d.packet_count,
        "byte_count": d.byte_count,
        "duration": d.duration,
        "packets_per_sec": d.packets_per_sec,
        "bytes_per_sec": d.bytes_per_sec,
        "features": d.features,
        "source": d.source,
    }


async def ingest_batch(
    session: AsyncSession,
    items: list[tuple[str | None, Detection]],
    config: DetectionConfig,
) -> list[IngestResult]:
    """Store detections and fold attacks into alerts. The caller commits.

    Detections correlate by (attack type, destination): an open alert for the
    same pair seen within the aggregation window absorbs the detection, so a
    flood raises one alert instead of thousands. Events and predictions are
    inserted in bulk, and each (type, destination) group takes its lock and
    loads its alert once per batch, which keeps a flood cheap to ingest.
    Returns one result per item, in order.
    """
    results: list[IngestResult | None] = [None] * len(items)
    stream_ids = [sid for sid, _ in items if sid is not None]
    existing: dict[str, int] = {}
    if stream_ids:
        rows = await session.execute(
            select(NetworkEvent.stream_id, NetworkEvent.id).where(
                NetworkEvent.stream_id.in_(stream_ids)
            )
        )
        existing = {sid: eid for sid, eid in rows.all() if sid is not None}

    fresh: list[int] = []
    seen_in_batch: set[str] = set()
    for index, (sid, _) in enumerate(items):
        if sid is not None and (sid in existing or sid in seen_in_batch):
            continue
        if sid is not None:
            seen_in_batch.add(sid)
        fresh.append(index)

    event_ids: dict[int, int] = {}
    if fresh:
        ids = await session.scalars(
            insert(NetworkEvent).returning(NetworkEvent.id, sort_by_parameter_order=True),
            [_event_row(*items[i]) for i in fresh],
        )
        event_ids = dict(zip(fresh, ids.all(), strict=True))
        await session.execute(
            insert(Prediction),
            [
                {
                    "event_id": event_ids[i],
                    "model_version": items[i][1].model_version,
                    "label": items[i][1].label,
                    "confidence": items[i][1].confidence,
                    "class_probs": items[i][1].class_probs,
                    "explanation": [e.model_dump() for e in items[i][1].explanation],
                    "risk_score": items[i][1].risk_score,
                    "risk_components": items[i][1].risk_components,
                    "severity": severity_for(items[i][1].risk_score),
                }
                for i in fresh
            ],
        )
    by_stream = {items[i][0]: event_ids[i] for i in fresh if items[i][0] is not None}
    for index, (sid, _) in enumerate(items):
        if index not in event_ids:
            event_id = existing.get(sid) or by_stream[sid]  # type: ignore[index]
            results[index] = IngestResult(event_id=event_id, duplicate=True)

    groups: dict[tuple[str, str], list[int]] = {}
    for index in fresh:
        d = items[index][1]
        if d.label == BENIGN_LABEL or d.risk_score < config.alert_min_risk:
            results[index] = IngestResult(event_id=event_ids[index])
        else:
            groups.setdefault((d.label, str(d.dst_ip)), []).append(index)

    window = timedelta(minutes=config.aggregation_window_minutes)
    links: list[dict] = []
    changed: dict[int, tuple[Alert, bool]] = {}  # alert id -> (alert, created in batch)
    # Sorted lock order keeps concurrent consumers from deadlocking.
    for label, dst in sorted(groups):
        indices = groups[(label, dst)]
        lock_key = f"alert:{label}:{dst}"
        await session.execute(select(func.pg_advisory_xact_lock(func.hashtext(lock_key))))
        first = items[indices[0]][1]
        alert = await session.scalar(
            select(Alert)
            .where(
                Alert.attack_type == label,
                Alert.destination_ip == first.dst_ip,
                Alert.status.in_(OPEN_ALERT_STATUSES),
                Alert.last_seen_at >= min(items[i][1].ts for i in indices) - window,
            )
            .order_by(Alert.last_seen_at.desc())
            .limit(1)
            .with_for_update()
        )
        for index in indices:
            d = items[index][1]
            severity = severity_for(d.risk_score)
            explanation = [e.model_dump() for e in d.explanation]
            created = escalated = False
            if alert is None or alert.last_seen_at < d.ts - window:
                alert = _new_alert(d, severity, explanation)
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
                created = True
                changed[alert.id] = (alert, True)
            else:
                escalated = _absorb(session, alert, d, severity, explanation)
                if escalated and alert.id not in changed:
                    changed[alert.id] = (alert, False)
            links.append({"alert_id": alert.id, "event_id": event_ids[index]})
            results[index] = IngestResult(
                event_id=event_ids[index], alert=alert, created=created, escalated=escalated
            )

    if links:
        await session.execute(insert(alert_events), links)
    for alert, created in changed.values():
        # Same transaction as the alert change: the delivery exists if and only
        # if the change commits (transactional outbox). One delivery per band.
        await enqueue_for_alert(session, alert, created=created)
    return [r for r in results if r is not None]


async def ingest_detection(
    session: AsyncSession,
    detection: Detection,
    config: DetectionConfig,
    stream_id: str | None = None,
) -> IngestResult:
    """Store one detection (see ingest_batch). The caller commits."""
    (result,) = await ingest_batch(session, [(stream_id, detection)], config)
    return result
