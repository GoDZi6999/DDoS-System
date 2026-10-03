"""Dashboard statistics, computed from the raw tables.

Fine at lab scale; pre-aggregated rollups (attack_statistics) are planned for
Phase 7 if query cost grows.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, NetworkEvent, Prediction
from app.models.enums import OPEN_ALERT_STATUSES, AlertStatus, Severity, severity_for
from app.schemas.detection import BENIGN_LABEL
from app.schemas.stats import (
    Bucket,
    Distribution,
    DistributionItem,
    StatsSummary,
    Timeseries,
    TimeseriesPoint,
    Window,
)
from app.services.errors import UnprocessableError

WINDOWS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}
BUCKETS: dict[str, timedelta] = {
    "1m": timedelta(minutes=1),
    "5m": timedelta(minutes=5),
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
}
MAX_POINTS = 1440
BUCKET_ORIGIN = datetime(2000, 1, 1, tzinfo=UTC)


def _joined_events():
    return (
        select(func.count())
        .select_from(NetworkEvent)
        .join(Prediction, Prediction.event_id == NetworkEvent.id)
    )


async def summary(session: AsyncSession, window: Window) -> StatsSummary:
    since = datetime.now(UTC) - WINDOWS[window]
    events = await session.scalar(_joined_events().where(NetworkEvent.ts >= since))
    attacks = await session.scalar(
        _joined_events().where(NetworkEvent.ts >= since, Prediction.label != BENIGN_LABEL)
    )
    by_status = {status: 0 for status in AlertStatus}
    for status, count in await session.execute(
        select(Alert.status, func.count()).group_by(Alert.status)
    ):
        by_status[status] = count
    by_severity = {severity: 0 for severity in Severity}
    for severity, count in await session.execute(
        select(Alert.severity, func.count())
        .where(Alert.status.in_(OPEN_ALERT_STATUSES))
        .group_by(Alert.severity)
    ):
        by_severity[severity] = count
    risk = await session.scalar(
        select(func.max(Alert.risk_score)).where(Alert.status.in_(OPEN_ALERT_STATUSES))
    )
    return StatsSummary(
        window=window,
        events=events or 0,
        attacks=attacks or 0,
        alerts_open=sum(by_status[s] for s in OPEN_ALERT_STATUSES),
        alerts_contained=by_status[AlertStatus.CONTAINED],
        alerts_by_status=by_status,
        open_alerts_by_severity=by_severity,
        risk_score=risk or 0,
        severity=severity_for(risk or 0),
    )


def _floor(ts: datetime, bucket: timedelta) -> datetime:
    return BUCKET_ORIGIN + ((ts - BUCKET_ORIGIN) // bucket) * bucket


async def timeseries(session: AsyncSession, window: Window, bucket: Bucket) -> Timeseries:
    span, step = WINDOWS[window], BUCKETS[bucket]
    if span / step > MAX_POINTS:
        raise UnprocessableError(f"bucket {bucket} is too small for window {window}")
    now = datetime.now(UTC)
    since = now - span
    bucket_col = func.date_bin(literal(step), NetworkEvent.ts, literal(BUCKET_ORIGIN))
    rows = await session.execute(
        select(
            bucket_col.label("bucket"),
            func.count().label("events"),
            func.count().filter(Prediction.label != BENIGN_LABEL).label("attacks"),
        )
        .select_from(NetworkEvent)
        .join(Prediction, Prediction.event_id == NetworkEvent.id)
        .where(NetworkEvent.ts >= since)
        .group_by("bucket")
    )
    counts = {row.bucket: (row.events, row.attacks) for row in rows}
    # Fill empty buckets so charts get an evenly spaced series.
    points = []
    cursor = _floor(since, step)
    while cursor <= now:
        events, attacks = counts.get(cursor, (0, 0))
        points.append(TimeseriesPoint(ts=cursor, events=events, attacks=attacks))
        cursor += step
    return Timeseries(window=window, bucket=bucket, points=points)


async def distribution(session: AsyncSession, window: Window) -> Distribution:
    since = datetime.now(UTC) - WINDOWS[window]
    count = func.count().label("count")
    rows = await session.execute(
        select(Prediction.label, count)
        .join(NetworkEvent, NetworkEvent.id == Prediction.event_id)
        .where(NetworkEvent.ts >= since)
        .group_by(Prediction.label)
        .order_by(count.desc(), Prediction.label)
    )
    items = [DistributionItem(label=label, count=n) for label, n in rows]
    return Distribution(window=window, items=items)
