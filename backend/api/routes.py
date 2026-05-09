from flask import Blueprint, jsonify, request, abort
import threading
import psutil
import time

from config.settings import settings
from core.state import active_config, blocked_ips
from core.scanning.realtime_scanner import run_deep_scan
from core.analyzer.ai_analyzer import analyze_threat
from db.database import log_alert, get_recent_alerts

# Simple in-memory rate limiter for analyze endpoint
_analyze_timestamps = {}
ANALYZE_RATE_LIMIT_SECONDS = 3

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    last = _analyze_timestamps.get(ip, 0)
    if now - last < ANALYZE_RATE_LIMIT_SECONDS:
        return True
    _analyze_timestamps[ip] = now
    return False

def run_deep_scan_and_emit(socketio):
    results = run_deep_scan(socketio)
    socketio.emit('scan_complete', results)
    for alert in results.get('threats', []):
        log_alert("deep_scan", alert['name'], alert['severity'], str(alert))

def register_routes(app, socketio):
    
    # ── Auth ────────────────────────────────────────────────────────
    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Missing JSON payload"}), 400

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"success": False, "error": "Username and password required"}), 400

        if username == settings.ADMIN_USERNAME and password == settings.ADMIN_PASSWORD:
            log_alert("auth", f"Admin login: {username}", "Low", "Successful authentication")
            return jsonify({"success": True, "token": "cybershield-auth-token-123"})

        log_alert("auth", f"Failed login attempt: {username}", "Medium", "Invalid credentials")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    # ── Deep Scan ───────────────────────────────────────────────────
    @app.route("/api/scan", methods=["POST"])
    def trigger_deep_scan():
        threading.Thread(
            target=run_deep_scan_and_emit,
            args=(socketio,),
            daemon=True
        ).start()
        return jsonify({"message": "Deep scan initiated."})

    # ── AI Analysis ─────────────────────────────────────────────────
    @app.route("/api/analyze", methods=["POST"])
    def analyze_input():
        client_ip = request.remote_addr

        if _is_rate_limited(client_ip):
            return jsonify({"error": "Rate limit exceeded. Please wait a moment."}), 429

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        threat_input = data.get("input", "").strip()
        if not threat_input:
            return jsonify({"error": "No input provided"}), 400

        if len(threat_input) > 2000:
            return jsonify({"error": "Input too long (max 2000 characters)"}), 400

        analysis = analyze_threat(threat_input)
        log_alert(
            "ai_analysis",
            threat_input[:120],
            analysis.get("severity", "Medium"),
            str(analysis)
        )
        return jsonify(analysis)

    # ── Alert History ───────────────────────────────────────────────
    @app.route("/api/history", methods=["GET"])
    def get_history():
        try:
            limit = min(int(request.args.get("limit", 50)), 200)
        except ValueError:
            limit = 50
        alerts = get_recent_alerts(limit=limit)
        return jsonify({"alerts": alerts, "count": len(alerts)})

    # ── System Stats ────────────────────────────────────────────────
    @app.route("/api/system_stats", methods=["GET"])
    def get_system_stats():
        try:
            stats = {
                "cpu_percent":     psutil.cpu_percent(interval=0.1),
                "memory_percent":  psutil.virtual_memory().percent,
                "disk_percent":    psutil.disk_usage('/').percent,
                "net_connections": len(psutil.net_connections(kind='inet')),
            }
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify(stats)

    # ── Admin: Config ───────────────────────────────────────────────
    @app.route("/api/admin/config", methods=["GET"])
    def get_admin_config():
        return jsonify({
            "active_config": active_config,
            "blocked_ips":   list(blocked_ips)
        })

    @app.route("/api/admin/config", methods=["POST"])
    def update_admin_config():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Missing payload"}), 400

        if "sniffing_paused" in data:
            active_config["sniffing_paused"] = bool(data["sniffing_paused"])
        if "ai_enabled" in data:
            active_config["ai_enabled"] = bool(data["ai_enabled"])

        log_alert("admin", "Config updated", "Low", str(data))
        return jsonify({"success": True, "config": active_config})

    # ── Admin: Blocklist ────────────────────────────────────────────
    @app.route("/api/admin/blocklist", methods=["POST"])
    def add_to_blocklist():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Missing payload"}), 400

        ip_address = data.get("ip", "").strip()
        if not ip_address:
            return jsonify({"error": "No IP provided"}), 400

        # Basic validation
        parts = ip_address.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return jsonify({"error": "Invalid IP address format"}), 400

        blocked_ips.add(ip_address)
        log_alert(
            "firewall",
            f"Banned IP: {ip_address}",
            "High",
            f"Manual admin block: {ip_address}"
        )
        return jsonify({"success": True, "blocked_ips": list(blocked_ips)})

    # ── Admin: Blocklist Remove ─────────────────────────────────────
    @app.route("/api/admin/blocklist", methods=["DELETE"])
    def remove_from_blocklist():
        data = request.get_json(silent=True)
        ip_address = data.get("ip", "").strip() if data else ""
        if ip_address in blocked_ips:
            blocked_ips.discard(ip_address)
            log_alert("firewall", f"Unbanned IP: {ip_address}", "Low", f"Admin unblock: {ip_address}")
            return jsonify({"success": True, "blocked_ips": list(blocked_ips)})
        return jsonify({"error": "IP not in blocklist"}), 404

    # ── Health Check ────────────────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "version": "2.0"}), 200