"""The machine API for customer applications and sensors, authenticated by API keys
(X-API-Key) rather than user logins. Admins manage keys under /api/v1/api-keys."""

from fastapi import APIRouter

from app.api.v2 import flows

router = APIRouter(prefix="/v2")
router.include_router(flows.router)
