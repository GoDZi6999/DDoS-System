from fastapi import APIRouter, Request, status

from app.api.deps import AdminUser, PaginationDep, SessionDep, actor_for
from app.schemas.api_key import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.schemas.common import Page
from app.services import api_keys as api_key_service

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("", response_model=Page[ApiKeyOut])
async def list_api_keys(_: AdminUser, session: SessionDep, page: PaginationDep) -> Page[ApiKeyOut]:
    keys, total = await api_key_service.list_keys(session, page.limit, page.offset)
    return Page(
        items=[ApiKeyOut.model_validate(k) for k in keys],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate, admin: AdminUser, request: Request, session: SessionDep
) -> ApiKeyCreated:
    """Create a key for the /v2 machine API. The response is the only time the key
    itself is shown; only its hash is stored."""
    api_key, key = await api_key_service.create_key(session, body, actor_for(admin, request))
    return ApiKeyCreated.model_validate(
        ApiKeyOut.model_validate(api_key).model_dump() | {"key": key}
    )


@router.post("/{key_id}/revoke", response_model=ApiKeyOut)
async def revoke_api_key(
    key_id: int, admin: AdminUser, request: Request, session: SessionDep
) -> ApiKeyOut:
    """Revoke a key immediately. Keys are kept (revoked) for the audit trail."""
    api_key = await api_key_service.revoke_key(session, key_id, actor_for(admin, request))
    return ApiKeyOut.model_validate(api_key)
