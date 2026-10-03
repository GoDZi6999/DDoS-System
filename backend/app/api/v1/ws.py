"""Live event feed for dashboards.

Protocol (see docs/API.md):
  client -> {"type": "auth", "token": "<access token>"}   within AUTH_TIMEOUT_S
  server -> {"type": "auth.ok", "user": {...}}
  server -> {"type": "alert.new" | "alert.updated", "data": {...}}   as they happen
The token travels in the first message rather than the URL so it never lands
in access logs. The server closes with code 4401 when authentication fails or
the access token expires; clients then reconnect with a fresh token.
"""

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.deps import authenticate_token
from app.services.notify import EVENTS_CHANNEL

router = APIRouter(tags=["realtime"])

AUTH_TIMEOUT_S = 5.0
POLL_INTERVAL_S = 1.0
CLOSE_UNAUTHORIZED = 4401


async def _wait_for_disconnect(websocket: WebSocket) -> None:
    # Messages sent after authentication are ignored.
    while (await websocket.receive())["type"] != "websocket.disconnect":
        pass


@router.websocket("/ws")
async def live_events(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=AUTH_TIMEOUT_S)
    except (TimeoutError, ValueError, KeyError, WebSocketDisconnect):
        await websocket.close(code=CLOSE_UNAUTHORIZED, reason="authentication required")
        return

    authenticated = None
    if isinstance(message, dict) and message.get("type") == "auth":
        token = message.get("token")
        if isinstance(token, str):
            async with websocket.app.state.sessionmaker() as session:
                authenticated = await authenticate_token(session, token)
    if authenticated is None:
        await websocket.close(code=CLOSE_UNAUTHORIZED, reason="invalid or expired token")
        return
    user, claims = authenticated

    # Subscribe before confirming, so no event is missed after "auth.ok".
    pubsub = websocket.app.state.redis.pubsub()
    await pubsub.subscribe(EVENTS_CHANNEL)
    client_gone = asyncio.create_task(_wait_for_disconnect(websocket))
    try:
        await websocket.send_json(
            {
                "type": "auth.ok",
                "user": {"id": user.id, "username": user.username, "role": user.role.value},
            }
        )
        while not client_gone.done():
            if datetime.now(UTC) >= claims.expires_at:
                await websocket.close(code=CLOSE_UNAUTHORIZED, reason="token expired")
                break
            event = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=POLL_INTERVAL_S
            )
            if event is not None:
                await websocket.send_text(event["data"].decode())
    except WebSocketDisconnect:
        pass
    finally:
        client_gone.cancel()
        await pubsub.unsubscribe(EVENTS_CHANNEL)
        await pubsub.aclose()
