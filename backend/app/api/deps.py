"""Shared request dependencies: database session, authentication, roles, audit actor."""

from typing import Annotated

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import AccessClaims, InvalidTokenError, decode_access_token
from app.db.session import get_session
from app.models import User
from app.models.enums import Role
from app.services.audit import Actor, ClientInfo

SessionDep = Annotated[AsyncSession, Depends(get_session)]

bearer_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"}
    )


async def authenticate_token(
    session: AsyncSession, token: str | None
) -> tuple[User, AccessClaims] | None:
    """Resolve an access token to an active user. Role and status are always read
    from the database, so changes apply immediately rather than at token expiry."""
    if not token:
        return None
    try:
        claims = decode_access_token(token)
    except InvalidTokenError:
        return None
    user = await session.get(User, claims.user_id)
    if user is None or not user.is_active or user.token_version != claims.token_version:
        return None
    return user, claims


async def get_current_user(
    session: SessionDep, token: Annotated[str | None, Depends(bearer_scheme)]
) -> User:
    if not token:
        raise unauthorized()
    result = await authenticate_token(session, token)
    if result is None:
        raise unauthorized("Invalid or expired token")
    return result[0]


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(role: Role):
    async def check(user: CurrentUser) -> User:
        if not user.role.includes(role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return Depends(check)


ViewerUser = Annotated[User, require_role(Role.VIEWER)]
AnalystUser = Annotated[User, require_role(Role.ANALYST)]
AdminUser = Annotated[User, require_role(Role.ADMIN)]


def client_info(request: Request) -> ClientInfo:
    user_agent = request.headers.get("user-agent")
    return ClientInfo(
        ip=request.client.host if request.client else None,
        user_agent=user_agent[:256] if user_agent else None,
    )


def actor_for(user: User, request: Request) -> Actor:
    return Actor(user_id=user.id, username=user.username, client=client_info(request))


class Pagination:
    def __init__(
        self,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> None:
        self.limit = limit
        self.offset = offset


PaginationDep = Annotated[Pagination, Depends()]
