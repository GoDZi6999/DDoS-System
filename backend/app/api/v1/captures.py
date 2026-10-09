from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from app.api.deps import AdminUser, AnalystUser, PaginationDep, SessionDep, ViewerUser, actor_for
from app.core.config import get_settings
from app.schemas.capture import CaptureOut
from app.schemas.common import Page
from app.services import captures as capture_service

router = APIRouter(prefix="/captures", tags=["captures"])


@router.post(
    "",
    response_model=CaptureOut,
    status_code=status.HTTP_202_ACCEPTED,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/octet-stream": {"schema": {"type": "string"}}},
        }
    },
)
async def upload_capture(
    request: Request,
    analyst: AnalystUser,
    session: SessionDep,
    filename: Annotated[str, Query(min_length=1, max_length=255)],
    raise_alerts: bool = True,
) -> CaptureOut:
    """Upload a packet capture (.pcap or .pcapng, e.g. saved from Wireshark) as the
    raw request body. It is queued for analysis by the real-time engine; poll
    GET /captures/{id} for the report. With `raise_alerts`, attacks found raise
    alerts and notifications like live traffic."""
    try:
        capture = await capture_service.store_upload(
            session,
            get_settings(),
            request.stream(),
            filename,
            raise_alerts,
            actor_for(analyst, request),
        )
    except capture_service.CaptureTooLarge as exc:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc)) from exc
    return CaptureOut.model_validate(capture)


@router.get("", response_model=Page[CaptureOut])
async def list_captures(
    _: ViewerUser, session: SessionDep, page: PaginationDep
) -> Page[CaptureOut]:
    """Newest first."""
    rows, total = await capture_service.list_captures(session, page.limit, page.offset)
    return Page(
        items=[CaptureOut.model_validate(c) for c in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{capture_id}", response_model=CaptureOut)
async def get_capture(capture_id: int, _: ViewerUser, session: SessionDep) -> CaptureOut:
    return CaptureOut.model_validate(await capture_service.get_capture(session, capture_id))


@router.delete("/{capture_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_capture(
    capture_id: int, admin: AdminUser, request: Request, session: SessionDep
) -> Response:
    """Delete the stored file. Alerts and flows it produced are kept, but lose
    their packet evidence."""
    await capture_service.delete_capture(
        session, get_settings(), capture_id, actor_for(admin, request)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
