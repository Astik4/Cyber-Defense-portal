import os
from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS

from config.settings import settings
from db.database import init_db
from api.routes import register_routes
from core.sniffing.packet_sniffer import start_sniffing

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))

def create_app():
    # Do NOT set static_folder here — we handle all static serving manually
    app = Flask(__name__, static_folder=None)
    app.config.from_object(settings)

    CORS(app, resources={r"/api/*": {"origins": "*"}})
    socketio = SocketIO(app, cors_allowed_origins="*")

    init_db()

    # ── Serve index.html at root ──────────────────────────────────
    @app.route('/')
    def index():
        return send_from_directory(FRONTEND_DIR, 'index.html')

    # ── Serve everything else in frontend/ (css, src, fonts, etc.) 
    @app.route('/<path:filename>')
    def static_files(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    # ── Register API + WebSocket routes ──────────────────────────
    register_routes(app, socketio)

    return app, socketio


if __name__ == '__main__':
    app, socketio = create_app()

    # Start background packet capture thread
    start_sniffing(socketio)

    # Run server
    socketio.run(
        app,
        host='0.0.0.0',
        port=settings.PORT,
        debug=settings.DEBUG
    )