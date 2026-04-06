"""
WebSocket Routes — Fixed
=========================
Fix applied: /ws/admin now validates a JWT query parameter before
accepting the connection. Unauthenticated clients are rejected with code 1008.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
import json
import jwt
import logging
import os
from typing import List

router = APIRouter(prefix="/ws", tags=["websockets"])
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM  = "HS256"


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Total: %d", len(self.active_connections))

    async def broadcast(self, message: dict):
        dead = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning("Failed to broadcast to WebSocket: %s", e)
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    async def send_to(self, websocket: WebSocket, message: dict):
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning("Failed to send to WebSocket: %s", e)
            self.disconnect(websocket)


# Global singleton reused across all broadcast calls
manager = ConnectionManager()


@router.websocket("/admin")
async def websocket_admin(websocket: WebSocket, token: str = Query(default=None)):
    """
    Authenticated WebSocket endpoint.
    FIX: Now validates JWT token from query parameter before accepting connection.
    Usage: ws://localhost:8000/ws/admin?token=<access_token>
    """
    # Validate JWT before accepting
    if not token:
        logger.warning("WebSocket connection rejected: no token provided.")
        await websocket.close(code=1008)  # Policy Violation
        return

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise ValueError("Invalid token type")
    except Exception as e:
        logger.warning("WebSocket authentication failed: %s", e)
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive — handle client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
