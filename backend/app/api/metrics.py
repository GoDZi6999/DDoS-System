"""Prometheus metrics, served at /metrics (outside /api/v1, so the dashboard's
proxy never exposes them; the API port is bound to localhost in Compose).

Request metrics are labelled by route template, not raw path, to keep label
cardinality bounded. Pipeline gauges are read from PostgreSQL and Redis when
Prometheus scrapes, so every worker is covered without its own exporter.
"""

import asyncio
import logging
import time

from fastapi import APIRouter, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    ProcessCollector,
    generate_latest,
)
from redis.exceptions import RedisError, ResponseError
from sqlalchemy import case, func, select
from sqlalchemy.exc import SQLAlchemyError

from app.models import Alert, NetworkEvent, NotificationDelivery, Prediction
from app.models.enums import OPEN_ALERT_STATUSES, DeliveryStatus, Severity
from app.schemas.detection import BENIGN_LABEL

logger = logging.getLogger(__name__)
router = APIRouter(include_in_schema=False)

REGISTRY = CollectorRegistry()
ProcessCollector(registry=REGISTRY)

REQUESTS = Counter(
    "argus_http_requests",
    "API requests by route template, method and status class",
    ["route", "method", "status"],
    registry=REGISTRY,
)
LATENCY = Histogram(
    "argus_http_request_duration_seconds",
    "API request duration by route template",
    ["route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    registry=REGISTRY,
)
OPEN_ALERTS = Gauge("argus_open_alerts", "Open alerts by severity", ["severity"], registry=REGISTRY)
FLOWS = Gauge(
    "argus_flows_last_5m",
    "Flows analysed in the last 5 minutes, by class",
    ["class"],
    registry=REGISTRY,
)
DELIVERIES = Gauge(
    "argus_notification_deliveries_24h",
    "Notification deliveries queued in the last 24 hours, by status",
    ["status"],
    registry=REGISTRY,
)
STREAM = Gauge(
    "argus_detection_stream",
    "Detection stream: entries not yet read (lag), read but unacknowledged "
    "(pending), and dead-lettered",
    ["state"],
    registry=REGISTRY,
)
SCRAPE_ERRORS = Counter(
    "argus_metrics_scrape_errors", "Pipeline gauges that could not be read", registry=REGISTRY
)

DETECTIONS_STREAM = "argus:detections"
DEAD_LETTER_STREAM = "argus:detections:dead"
CONSUMER_GROUP = "alert-engine"
QUERY_TIMEOUT_S = 3.0


def route_template(request: Request) -> str:
    """The path with parameter values put back as {names}: "/api/v1/alerts/{alert_id}"."""
    if request.scope.get("route") is None:
        return "unmatched"  # 404s: never label by an arbitrary client path
    path = request.url.path
    for name, value in request.path_params.items():
        path = path.replace(f"/{value}", f"/{{{name}}}", 1)
    return path


def observe(route: str, method: str, status: int, seconds: float) -> None:
    REQUESTS.labels(route, method, f"{status // 100}xx").inc()
    LATENCY.labels(route).observe(seconds)


async def _database_gauges(request: Request) -> None:
    async with request.app.state.sessionmaker() as session:
        counts = dict(
            (
                await session.execute(
                    select(Alert.severity, func.count())
                    .where(Alert.status.in_(OPEN_ALERT_STATUSES))
                    .group_by(Alert.severity)
                )
            ).all()
        )
        for severity in Severity:
            OPEN_ALERTS.labels(severity.value).set(counts.get(severity, 0))

        is_attack = case((Prediction.label == BENIGN_LABEL, "benign"), else_="attack")
        flows = dict(
            (
                await session.execute(
                    select(is_attack, func.count())
                    .select_from(NetworkEvent)
                    .join(Prediction, Prediction.event_id == NetworkEvent.id)
                    .where(NetworkEvent.ts >= func.now() - func.make_interval(0, 0, 0, 0, 0, 5))
                    .group_by(is_attack)
                )
            ).all()
        )
        for label in ("benign", "attack"):
            FLOWS.labels(label).set(flows.get(label, 0))

        deliveries = dict(
            (
                await session.execute(
                    select(NotificationDelivery.status, func.count())
                    .where(
                        NotificationDelivery.created_at
                        >= func.now() - func.make_interval(0, 0, 0, 1)
                    )
                    .group_by(NotificationDelivery.status)
                )
            ).all()
        )
        for status in DeliveryStatus:
            DELIVERIES.labels(status.value).set(deliveries.get(status, 0))


async def _stream_gauges(request: Request) -> None:
    redis = request.app.state.redis
    lag = pending = 0
    try:
        for group in await redis.xinfo_groups(DETECTIONS_STREAM):
            if group["name"] in (CONSUMER_GROUP, CONSUMER_GROUP.encode()):
                lag, pending = group.get("lag") or 0, group.get("pending") or 0
    except ResponseError:  # stream not created yet
        pass
    STREAM.labels("lag").set(lag)
    STREAM.labels("pending").set(pending)
    STREAM.labels("dead_lettered").set(await redis.xlen(DEAD_LETTER_STREAM))


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    for collect in (_database_gauges, _stream_gauges):
        try:
            await asyncio.wait_for(collect(request), QUERY_TIMEOUT_S)
        except (SQLAlchemyError, RedisError, OSError, TimeoutError):
            SCRAPE_ERRORS.inc()
            logger.warning("Could not read %s for /metrics", collect.__name__, exc_info=True)
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


class Timer:
    def __init__(self) -> None:
        self.start = time.perf_counter()

    def elapsed(self) -> float:
        return time.perf_counter() - self.start
