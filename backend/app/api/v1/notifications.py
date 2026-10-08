from typing import Annotated

from fastapi import APIRouter, Query, Request, status

from app.api.deps import AdminUser, PaginationDep, SessionDep, actor_for
from app.models.enums import DeliveryStatus
from app.schemas.common import Page
from app.schemas.notification import (
    ChannelCreate,
    ChannelOut,
    ChannelUpdate,
    DeliveryOut,
    TestResult,
)
from app.services import notifications as service

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("/channels", response_model=list[ChannelOut])
async def list_channels(_: AdminUser, session: SessionDep) -> list[ChannelOut]:
    return await service.list_channels(session)


@router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: ChannelCreate, admin: AdminUser, request: Request, session: SessionDep
) -> ChannelOut:
    channel = await service.create_channel(session, body, actor_for(admin, request))
    return await service.channel_out(session, channel)


@router.get("/channels/{channel_id}", response_model=ChannelOut)
async def get_channel(channel_id: int, _: AdminUser, session: SessionDep) -> ChannelOut:
    return await service.channel_out(session, await service.get_channel(session, channel_id))


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
async def update_channel(
    channel_id: int, body: ChannelUpdate, admin: AdminUser, request: Request, session: SessionDep
) -> ChannelOut:
    """Channels are disabled rather than deleted, so the delivery log keeps them."""
    channel = await service.update_channel(session, channel_id, body, actor_for(admin, request))
    return await service.channel_out(session, channel)


@router.post(
    "/channels/{channel_id}/test",
    response_model=TestResult,
    status_code=status.HTTP_202_ACCEPTED,
)
async def test_channel(
    channel_id: int, admin: AdminUser, request: Request, session: SessionDep
) -> TestResult:
    """Queue a test message; its outcome appears in the delivery log."""
    delivery_id = await service.send_test(session, channel_id, actor_for(admin, request))
    return TestResult(delivery_id=delivery_id)


@router.get("/deliveries", response_model=Page[DeliveryOut])
async def list_deliveries(
    _: AdminUser,
    session: SessionDep,
    page: PaginationDep,
    channel_id: int | None = None,
    alert_id: int | None = None,
    status_: Annotated[list[DeliveryStatus] | None, Query(alias="status")] = None,
) -> Page[DeliveryOut]:
    return await service.list_deliveries(
        session,
        channel_id=channel_id,
        alert_id=alert_id,
        statuses=status_,
        limit=page.limit,
        offset=page.offset,
    )
