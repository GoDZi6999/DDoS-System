from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import AwareDatetime, IPvAnyAddress

from app.api.deps import PaginationDep, SessionDep, ViewerUser
from app.schemas.common import Page
from app.schemas.event import EventDetail, EventSummary
from app.services import events as event_service

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=Page[EventSummary])
async def list_events(
    _: ViewerUser,
    session: SessionDep,
    page: PaginationDep,
    label: Annotated[str | None, Query(max_length=32)] = None,
    ip: Annotated[IPvAnyAddress | None, Query(description="Source or destination")] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    min_risk: Annotated[int | None, Query(ge=0, le=100)] = None,
) -> Page[EventSummary]:
    filters = event_service.EventFilters(
        label=label, ip=ip, since=since, until=until, min_risk=min_risk
    )
    items, total = await event_service.list_events(session, filters, page.limit, page.offset)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(event_id: int, _: ViewerUser, session: SessionDep) -> EventDetail:
    """One flow with its prediction, SHAP explanation and risk breakdown."""
    return await event_service.get_event(session, event_id)
