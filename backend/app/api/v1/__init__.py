from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    api_keys,
    audit,
    auth,
    captures,
    config,
    events,
    notifications,
    sensors,
    stats,
    users,
    ws,
)

router = APIRouter(prefix="/api/v1")
for module in (
    auth,
    users,
    alerts,
    events,
    stats,
    sensors,
    config,
    audit,
    notifications,
    api_keys,
    captures,
    ws,
):
    router.include_router(module.router)
