"""User administration (admin only)."""

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models import User
from app.models.enums import Role
from app.schemas.user import UserCreate, UserUpdate
from app.services.audit import Actor, record_audit
from app.services.auth import end_all_sessions
from app.services.errors import ConflictError, NotFoundError


def _snapshot(user: User) -> dict[str, Any]:
    return {
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
    }


async def list_users(session: AsyncSession, limit: int, offset: int) -> tuple[list[User], int]:
    total = await session.scalar(select(func.count()).select_from(User))
    users = await session.scalars(select(User).order_by(User.id).limit(limit).offset(offset))
    return list(users), total or 0


async def get_user(session: AsyncSession, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found")
    return user


async def create_user(session: AsyncSession, data: UserCreate, actor: Actor) -> User:
    user = User(
        username=data.username,
        email=data.email,
        role=data.role,
        password_hash=hash_password(data.password),
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("Username or email already exists") from exc
    record_audit(
        session, actor, "user.created", entity_type="user", entity_id=user.id, after=_snapshot(user)
    )
    await session.commit()
    return user


def _removes_admin(user: User, data: UserUpdate, fields: set[str]) -> bool:
    if user.role != Role.ADMIN or not user.is_active:
        return False
    demoted = "role" in fields and data.role not in (None, Role.ADMIN)
    deactivated = "is_active" in fields and data.is_active is False
    return demoted or deactivated


async def update_user(session: AsyncSession, user_id: int, data: UserUpdate, actor: Actor) -> User:
    fields = data.model_fields_set
    user = await get_user(session, user_id)

    if _removes_admin(user, data, fields):
        # Lock every active admin in id order (so concurrent requests cannot
        # deadlock), then re-check: there must always be one active admin left.
        admins = await session.scalars(
            select(User)
            .where(User.role == Role.ADMIN, User.is_active.is_(True))
            .order_by(User.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        others = [admin for admin in admins if admin.id != user.id]
        if _removes_admin(user, data, fields) and not others:
            raise ConflictError("At least one active admin is required")

    before = _snapshot(user)
    if data.role is not None:
        user.role = data.role
    if "email" in fields:
        user.email = data.email
    if data.is_active is not None:
        user.is_active = data.is_active
    password_reset = data.password is not None
    if password_reset:
        user.password_hash = hash_password(data.password)
    if password_reset or data.is_active is False:
        await end_all_sessions(session, user)

    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("Email already in use") from exc
    after = _snapshot(user) | ({"password_reset": True} if password_reset else {})
    record_audit(
        session,
        actor,
        "user.updated",
        entity_type="user",
        entity_id=user.id,
        before=before,
        after=after,
    )
    await session.commit()
    return user
