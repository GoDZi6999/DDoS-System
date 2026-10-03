from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.user import Password


class TokenPair(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 (not a secret)
    expires_in: int = Field(description="Access token lifetime in seconds")
    refresh_token: str
    refresh_expires_in: int = Field(description="Refresh token lifetime in seconds")


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=512)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(max_length=128)
    new_password: Password
