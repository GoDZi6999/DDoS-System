from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import AwareDatetime

from app.api.deps import AdminUser, PaginationDep, SessionDep
from app.schemas.audit import AuditOut
from app.schemas.common import Page
from app.services.audit import AuditFilters, list_audit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditOut])
async def list_entries(
    _: AdminUser,
    session: SessionDep,
    page: PaginationDep,
    actor: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    entity_type: Annotated[str | None, Query(max_length=32)] = None,
    entity_id: Annotated[str | None, Query(max_length=64)] = None,
    since: AwareDatetime | None = None,
    until: AwareDatetime | None = None,
) -> Page[AuditOut]:
    """Newest first. The log is append-only; there are no endpoints to change it."""
    filters = AuditFilters(
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        since=since,
        until=until,
    )
    entries, total = await list_audit(session, filters, page.limit, page.offset)
    return Page(
        items=[AuditOut.model_validate(e) for e in entries],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )
