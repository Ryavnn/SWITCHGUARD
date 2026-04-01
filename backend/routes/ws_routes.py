from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
import json
import logging
from typing import List, Dict

router = APIRouter(prefix="/ws", tags=["websockets"])
logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket Client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to WS. Removing connection. Error: {str(e)}")
                dead_connections.append(connection)
        
        for dead in dead_connections:
            self.disconnect(dead)


# Global instance to be used everywhere
manager = ConnectionManager()


@router.websocket("/admin")
async def websocket_admin(websocket: WebSocket):
    # In a real enterprise app, we evaluate the JWT sent in the query parameter here before accepting.
    # For project scope, we assume /ws/admin is connected to by the Admin dashboard which passes JWT locally.
    await manager.connect(websocket)
    try:
        while True:
            # We only listen for basic pings to keep connection alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
