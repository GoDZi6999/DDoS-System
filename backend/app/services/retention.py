"""Data retention for the high-volume tables.

A flow (network_events, with its prediction) is deleted once it is older than
EVENT_RETENTION_DAYS, unless it is evidence for an alert that is still open or
was closed less than EVIDENCE_RETENTION_DAYS ago. Finished notification
deliveries are kept for DELIVERY_RETENTION_DAYS. Alerts, notes and the audit
log are never purged.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import Alert, NetworkEvent, NotificationDelivery, alert_events
from app.models.enums import DeliveryStatus
from app.services.audit import SYSTEM_ACTOR, record_audit

BATCH_SIZE = 5000
# Arbitrary constant: lets only one worker purge at a time.
PURGE_LOCK_ID = 7_210_001


@dataclass
class PurgeResult:
    events: int = 0
    deliveries: int = 0
    skipped: bool = False


async def _locked(session: AsyncSession) -> bool:
    """Transaction-scoped lock: concurrent workers skip instead of both purging."""
    return bool(await session.scalar(select(func.pg_try_advisory_xact_lock(PURGE_LOCK_ID))))


async def purge(
    session: AsyncSession, settings: Settings, now: datetime | None = None
) -> PurgeResult:
    now = now or datetime.now(UTC)
    result = PurgeResult()
    event_cutoff = now - timedelta(days=settings.event_retention_days)
    evidence_cutoff = now - timedelta(days=settings.evidence_retention_days)
    delivery_cutoff = now - timedelta(days=settings.delivery_retention_days)

    protected = exists(
        select(1)
        .select_from(alert_events.join(Alert, Alert.id == alert_events.c.alert_id))
        .where(
            alert_events.c.event_id == NetworkEvent.id,
            or_(Alert.resolved_at.is_(None), Alert.resolved_at >= evidence_cutoff),
        )
    )
    # Batches keep each transaction (and its locks) short on large tables.
    while True:
        if not await _locked(session):
            await session.rollback()
            result.skipped = True
            return result
        batch = (
            select(NetworkEvent.id)
            .where(NetworkEvent.ts < event_cutoff, ~protected)
            .limit(BATCH_SIZE)
            .scalar_subquery()
        )
        deleted = (
            await session.execute(delete(NetworkEvent).where(NetworkEvent.id.in_(batch)))
        ).rowcount or 0
        await session.commit()
        result.events += deleted
        if deleted < BATCH_SIZE:
            break

    if not await _locked(session):
        await session.rollback()
        result.skipped = True
        return result
    result.deliveries = (
        await session.execute(
            delete(NotificationDelivery).where(
                and_(
                    NotificationDelivery.created_at < delivery_cutoff,
                    NotificationDelivery.status != DeliveryStatus.PENDING,
                )
            )
        )
    ).rowcount or 0
    if result.events or result.deliveries:
        record_audit(
            session,
            SYSTEM_ACTOR,
            "retention.purged",
            after={
                "network_events": result.events,
                "notification_deliveries": result.deliveries,
                "event_retention_days": settings.event_retention_days,
                "evidence_retention_days": settings.evidence_retention_days,
            },
        )
    await session.commit()
    return result
