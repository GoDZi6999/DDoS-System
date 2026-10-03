from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser, SessionDep, actor_for, client_info, unauthorized
from app.core.config import get_settings
from app.schemas.auth import PasswordChange, RefreshRequest, TokenPair
from app.schemas.user import UserOut
from app.services import auth as auth_service
from app.services.auth import AuthError, IssuedTokens, LoginThrottle, LoginThrottled

router = APIRouter(prefix="/auth", tags=["auth"])


def _token_pair(tokens: IssuedTokens) -> TokenPair:
    now = datetime.now(UTC)
    return TokenPair(
        access_token=tokens.access.token,
        expires_in=int((tokens.access.expires_at - now).total_seconds()),
        refresh_token=tokens.refresh_token,
        refresh_expires_in=int((tokens.refresh_expires_at - now).total_seconds()),
    )


@router.post(
    "/login",
    response_model=TokenPair,
    responses={401: {"description": "Bad credentials"}, 429: {"description": "Throttled"}},
)
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()], request: Request, session: SessionDep
) -> TokenPair:
    """OAuth2 password flow (form fields `username` and `password`).

    Also backs the Authorize button in Swagger UI.
    """
    throttle = LoginThrottle(request.app.state.redis, get_settings())
    try:
        tokens = await auth_service.login(
            session, throttle, form.username, form.password, client_info(request)
        )
    except LoginThrottled as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed login attempts; try again later",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except AuthError as exc:
        raise unauthorized(str(exc)) from exc
    return _token_pair(tokens)


@router.post("/refresh", response_model=TokenPair, responses={401: {"description": "Invalid"}})
async def refresh(body: RefreshRequest, request: Request, session: SessionDep) -> TokenPair:
    """Exchange a refresh token for a new pair. Each refresh token works once."""
    try:
        tokens = await auth_service.refresh(session, body.refresh_token, client_info(request))
    except AuthError as exc:
        raise unauthorized(str(exc)) from exc
    return _token_pair(tokens)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, request: Request, session: SessionDep) -> Response:
    """Revoke a refresh token. Access tokens expire on their own (15 minutes by default)."""
    await auth_service.logout(session, body.refresh_token, client_info(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={400: {"description": "Current password wrong or unchanged"}},
)
async def change_password(
    body: PasswordChange, user: CurrentUser, request: Request, session: SessionDep
) -> Response:
    """Change your own password. Ends all of your sessions, including this one."""
    try:
        await auth_service.change_password(
            session, user, body.current_password, body.new_password, actor_for(user, request)
        )
    except AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
