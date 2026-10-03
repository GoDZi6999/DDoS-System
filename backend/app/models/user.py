import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Identity, String, func, true
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, str_enum
from app.models.enums import Role


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str | None] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(str_enum(Role, "user_role"))
    is_active: Mapped[bool] = mapped_column(default=True, server_default=true())
    # Bumped on password change, deactivation or refresh-token reuse; access
    # tokens carry it, so bumping invalidates every outstanding token at once.
    token_version: Mapped[int] = mapped_column(default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    last_login_at: Mapped[datetime | None]


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # All tokens descending from one login share a family; reuse of a rotated
    # token revokes the whole family.
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
