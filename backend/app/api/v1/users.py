from fastapi import APIRouter, Request, status

from app.api.deps import AdminUser, PaginationDep, SessionDep, actor_for
from app.schemas.common import Page
from app.schemas.user import UserCreate, UserOut, UserUpdate
from app.services import users as user_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=Page[UserOut])
async def list_users(_: AdminUser, session: SessionDep, page: PaginationDep) -> Page[UserOut]:
    users, total = await user_service.list_users(session, page.limit, page.offset)
    return Page(
        items=[UserOut.model_validate(u) for u in users],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate, admin: AdminUser, request: Request, session: SessionDep
) -> UserOut:
    user = await user_service.create_user(session, body, actor_for(admin, request))
    return UserOut.model_validate(user)


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: int, _: AdminUser, session: SessionDep) -> UserOut:
    return UserOut.model_validate(await user_service.get_user(session, user_id))


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int, body: UserUpdate, admin: AdminUser, request: Request, session: SessionDep
) -> UserOut:
    """Change role, email or active state, or reset a password. Users are deactivated,
    never deleted, so the audit trail keeps referring to them."""
    user = await user_service.update_user(session, user_id, body, actor_for(admin, request))
    return UserOut.model_validate(user)
