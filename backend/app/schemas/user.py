from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.models.enums import Role
from app.schemas.common import ORMModel

# Stored lowercase; the pattern is checked before lowercasing, so it allows both cases.
Username = Annotated[
    str, StringConstraints(strip_whitespace=True, to_lower=True, pattern=r"^[A-Za-z0-9_.-]{3,64}$")
]
# Length-based policy (NIST SP 800-63B): no composition rules, long passphrases allowed.
Password = Annotated[str, Field(min_length=12, max_length=128)]


class UserRef(ORMModel):
    id: int
    username: str


class UserOut(ORMModel):
    id: int
    username: str
    email: str | None
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Username
    password: Password
    role: Role
    email: EmailStr | None = None


class UserUpdate(BaseModel):
    """Only the fields sent are changed; `email: null` removes the address."""

    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None
    email: EmailStr | None = None
    password: Password | None = None
