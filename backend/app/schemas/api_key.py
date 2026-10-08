from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import ApiScope
from app.schemas.common import ORMModel


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    scopes: list[ApiScope] = Field(min_length=1, max_length=len(ApiScope))


class ApiKeyOut(ORMModel):
    id: int
    name: str
    prefix: str
    scopes: list[ApiScope]
    created_by_id: int | None
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="The API key. Shown only once: store it now.")
