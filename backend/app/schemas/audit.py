from datetime import datetime
from typing import Any

from pydantic import IPvAnyAddress

from app.schemas.common import ORMModel


class AuditOut(ORMModel):
    id: int
    ts: datetime
    actor_id: int | None
    actor: str
    action: str
    entity_type: str | None
    entity_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ip: IPvAnyAddress | None
    user_agent: str | None
