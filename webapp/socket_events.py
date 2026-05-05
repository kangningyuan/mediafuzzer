"""SocketIO event handlers for the webapp."""

from __future__ import annotations

import logging

from flask import request
from flask_socketio import SocketIO, join_room

from .session_state import get_session, _DEFAULT_SID

logger = logging.getLogger("mediafuzzer.webapp.socket")

_SHARED_ROOM = "mediafuzzer"


def register_socket_events(socketio: SocketIO) -> None:
    """Register all SocketIO event handlers."""

    @socketio.on("connect")
    def on_connect():
        sid = request.sid
        join_room(_SHARED_ROOM)
        session = get_session(_DEFAULT_SID)
        logger.info("Client connected: %s", sid)
        socketio.emit(
            "pipeline:state",
            {
                "step": session.current_step,
                "status": session.step_status,
                "message": "Connected to MediaFuzzer",
            },
            room=_SHARED_ROOM,
        )

    @socketio.on("disconnect")
    def on_disconnect():
        sid = request.sid
        logger.info("Client disconnected: %s", sid)
