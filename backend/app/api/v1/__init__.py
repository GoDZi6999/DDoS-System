from fastapi import APIRouter

from app.api.v1 import (
    alerts,
    audit,
    auth,
    config,
    events,
    notifications,
    sensors,
    stats,
    users,
    ws,
)

router = APIRouter(prefix="/api/v1")
for module in (auth, users, alerts, events, stats, sensors, config, audit, notifications, ws):
    router.include_router(module.router)
