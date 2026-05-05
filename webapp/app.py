"""Flask app factory and entry point for MediaFuzzer Webapp."""

from __future__ import annotations

import logging
import os
import sys

from flask import Flask, current_app
from flask_socketio import SocketIO


def create_app() -> Flask:
    """Create and configure the Flask application."""
    webapp_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(webapp_dir, "templates"),
        static_folder=os.path.join(webapp_dir, "static"),
    )
    app.config["SECRET_KEY"] = os.urandom(24).hex()

    # Configure terminal logging for webapp background tasks
    _setup_logging()

    sio = SocketIO(async_mode="threading", cors_allowed_origins="*")
    sio.init_app(app)
    app.extensions["socketio"] = sio

    from .routes import main_bp
    app.register_blueprint(main_bp)

    from .socket_events import register_socket_events
    register_socket_events(sio)

    return app


def _setup_logging() -> None:
    """Configure logging so webapp background tasks output to terminal."""
    webapp_logger = logging.getLogger("mediafuzzer.webapp")
    if webapp_logger.handlers:
        return  # Already configured

    root_logger = logging.getLogger("mediafuzzer")
    root_logger.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root_logger.addHandler(console)


def get_socketio() -> SocketIO:
    """Get the SocketIO instance attached to the current Flask app."""
    return current_app.extensions["socketio"]


if __name__ == "__main__":
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from config.settings import load_settings
    load_settings()

    app = create_app()
    sio = app.extensions["socketio"]
    print("MediaFuzzer Webapp starting on http://localhost:5000")
    sio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
