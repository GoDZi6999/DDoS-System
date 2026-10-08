from datetime import datetime

from sqlalchemy import ForeignKey, Identity, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ApiKey(Base):
    """A credential for machine clients of the /v2 API (sensors, customer apps).

    Only the SHA-256 of the key is stored; the key itself is shown once, when it
    is created. Keys are revoked, never deleted, so the audit trail keeps
    referring to them."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    # The public part of the key ("argus_<prefix>_..."), for recognising it in lists.
    prefix: Mapped[str] = mapped_column(String(16), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Subset of ApiScope values.
    scopes: Mapped[list[str]] = mapped_column(JSONB)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
