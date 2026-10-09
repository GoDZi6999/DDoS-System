from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from pydantic import AwareDatetime, IPvAnyAddress

from app.api.deps import AnalystUser, PaginationDep, SessionDep, ViewerUser, actor_for
from app.core.config import get_settings
from app.models.enums import AlertStatus, Severity
from app.schemas.alert import (
    AlertDetail,
    AlertSummary,
    AssigneeUpdate,
    NoteCreate,
    NoteOut,
    StatusChange,
)
from app.schemas.common import Page
from app.schemas.event import EventSummary
from app.services import alerts as alert_service
from app.services import captures as capture_service
from app.services import events as event_service
from app.services.audit import record_audit
from app.services.capture_analysis import CaptureError, carve
from app.services.errors import UnprocessableError
from app.services.notify import publish

router = APIRouter(prefix="/alerts", tags=["alerts"])


async def _updated(request: Request, session: SessionDep, alert_id: int) -> AlertDetail:
    """Return the fresh alert detail and notify live dashboards."""
    detail = await alert_service.get_alert_detail(session, alert_id)
    summary = AlertSummary(**detail.model_dump(include=set(AlertSummary.model_fields)))
    await publish(request.app.state.redis, "alert.updated", summary.model_dump(mode="json"))
    return detail


@router.get("", response_model=Page[AlertSummary])
async def list_alerts(
    _: ViewerUser,
    session: SessionDep,
    page: PaginationDep,
    status_: Annotated[list[AlertStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    attack_type: Annotated[str | None, Query(max_length=32)] = None,
    ip: Annotated[IPvAnyAddress | None, Query(description="Source or destination")] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
    sort: Literal["last_seen", "risk"] = "last_seen",
) -> Page[AlertSummary]:
    filters = alert_service.AlertFilters(
        statuses=tuple(status_ or ()),
        severities=tuple(severity or ()),
        attack_type=attack_type,
        ip=ip,
        since=since,
        until=until,
        sort=sort,
    )
    items, total = await alert_service.list_alerts(session, filters, page.limit, page.offset)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: int, _: ViewerUser, session: SessionDep) -> AlertDetail:
    return await alert_service.get_alert_detail(session, alert_id)


@router.get("/{alert_id}/events", response_model=Page[EventSummary])
async def list_alert_events(
    alert_id: int, _: ViewerUser, session: SessionDep, page: PaginationDep
) -> Page[EventSummary]:
    await alert_service.get_alert(session, alert_id)
    filters = event_service.EventFilters(alert_id=alert_id)
    items, total = await event_service.list_events(session, filters, page.limit, page.offset)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.get(
    "/{alert_id}/evidence.pcap",
    response_class=Response,
    responses={200: {"content": {"application/vnd.tcpdump.pcap": {}}}},
)
async def download_evidence(
    alert_id: int, analyst: AnalystUser, request: Request, session: SessionDep
) -> Response:
    """The alert's packets as a pcap file for Wireshark, with the capture's
    original timestamps. Available for alerts raised from uploaded captures
    (`evidence_capture_id` in the alert detail); 422 otherwise."""
    evidence = await capture_service.evidence_request(session, get_settings(), alert_id)
    try:
        data, packets, truncated = await run_in_threadpool(
            carve, evidence.path, evidence.flows, capture_service.EVIDENCE_MAX_PACKETS
        )
    except CaptureError as exc:
        raise UnprocessableError(str(exc)) from exc
    if not packets:
        raise UnprocessableError("None of the alert's packets were found in the capture")
    record_audit(
        session,
        actor_for(analyst, request),
        "alert.evidence_downloaded",
        entity_type="alert",
        entity_id=alert_id,
        after={"capture_id": evidence.capture.id, "packets": packets, "truncated": truncated},
    )
    await session.commit()
    return Response(
        data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="argusai-alert-{alert_id}.pcap"',
            "X-Evidence-Packets": str(packets),
            "X-Evidence-Truncated": "true" if truncated else "false",
        },
    )


@router.post("/{alert_id}/ack", response_model=AlertDetail)
async def acknowledge(
    alert_id: int, user: AnalystUser, request: Request, session: SessionDep
) -> AlertDetail:
    """NEW -> INVESTIGATING, recording who acknowledged the alert."""
    await alert_service.acknowledge(session, alert_id, actor_for(user, request))
    return await _updated(request, session, alert_id)


@router.patch("/{alert_id}/status", response_model=AlertDetail)
async def change_status(
    alert_id: int, body: StatusChange, user: AnalystUser, request: Request, session: SessionDep
) -> AlertDetail:
    """Move the alert through the workflow; invalid transitions return 409."""
    await alert_service.change_status(
        session, alert_id, body.status, actor_for(user, request), body.note
    )
    return await _updated(request, session, alert_id)


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
async def add_note(
    alert_id: int, body: NoteCreate, user: AnalystUser, request: Request, session: SessionDep
) -> NoteOut:
    return await alert_service.add_note(session, alert_id, body.body, actor_for(user, request))


@router.put("/{alert_id}/assignee", response_model=AlertDetail)
async def set_assignee(
    alert_id: int, body: AssigneeUpdate, user: AnalystUser, request: Request, session: SessionDep
) -> AlertDetail:
    await alert_service.set_assignee(session, alert_id, body.user_id, actor_for(user, request))
    return await _updated(request, session, alert_id)
