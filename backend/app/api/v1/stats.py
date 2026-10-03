from fastapi import APIRouter

from app.api.deps import SessionDep, ViewerUser
from app.schemas.stats import Bucket, Distribution, StatsSummary, Timeseries, Window
from app.services import stats as stats_service

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary", response_model=StatsSummary)
async def summary(_: ViewerUser, session: SessionDep, window: Window = "24h") -> StatsSummary:
    return await stats_service.summary(session, window)


@router.get("/timeseries", response_model=Timeseries)
async def timeseries(
    _: ViewerUser, session: SessionDep, window: Window = "24h", bucket: Bucket = "15m"
) -> Timeseries:
    """Events and attacks per time bucket, with empty buckets filled in."""
    return await stats_service.timeseries(session, window, bucket)


@router.get("/distribution", response_model=Distribution)
async def distribution(_: ViewerUser, session: SessionDep, window: Window = "24h") -> Distribution:
    """Flow counts per predicted label (benign included)."""
    return await stats_service.distribution(session, window)
