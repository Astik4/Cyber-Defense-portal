from flask import jsonify, request
import threading
import psutil
import time
import random
import socket

from config.settings import settings
from core.state import active_config, blocked_ips, active_rules
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
    # Track if sniffing has been started in this worker process
    sniffer_started = False
    sniffer_lock = threading.Lock()

    @socketio.on('connect')
    def handle_connect(auth=None):
        nonlocal sniffer_started
        with sniffer_lock:
            if not sniffer_started:
                try:
                    from core.sniffing.packet_sniffer import start_sniffing
                    start_sniffing(socketio)
                    print("Lazy-started packet sniffer and simulation threads on client connect event.")
                except Exception as e:
                    print(f"Error starting sniffer on connect: {e}")
                sniffer_started = True

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

        for key in ["sniffing_paused", "ai_enabled", "emergency_lockdown", "honeypot_active", "reverse_tracing_active", "db_encryption_active", "simulation_active"]:
            if key in data:
                active_config[key] = bool(data[key])

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

    # ── Processes ───────────────────────────────────────────────────
    @app.route("/api/processes", methods=["GET"])
    def get_processes():
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                try:
                    pinfo = proc.info
                    cpu = pinfo.get('cpu_percent') or 0.0
                    mem = pinfo.get('memory_info').rss if pinfo.get('memory_info') else 0
                    status = pinfo.get('status') or 'unknown'
                    name = pinfo.get('name') or 'unknown'
                    
                    suspicious = False
                    critical = False
                    susp_names = ['netcat', 'nc', 'nmap', 'wireshark', 'mimikatz', 'hydra', 'john', 'hashcat', 'metasploit', 'exploit']
                    if any(x in name.lower() for x in susp_names):
                        suspicious = True
                    
                    if cpu > 80.0 or mem > 500 * 1024 * 1024:
                        critical = True
                        
                    processes.append({
                        "pid": pinfo['pid'],
                        "name": name,
                        "cpu": cpu,
                        "mem": mem,
                        "status": status,
                        "suspicious": suspicious,
                        "critical": critical
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            return jsonify({"processes": processes[:30]})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Connections ─────────────────────────────────────────────────
    @app.route("/api/connections", methods=["GET"])
    def get_connections():
        try:
            connections = []
            conns = psutil.net_connections(kind='inet')
            for conn in conns:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
                status = conn.status
                pid = conn.pid
                
                external = False
                if conn.raddr:
                    rip = conn.raddr.ip
                    if not (rip.startswith("127.") or rip.startswith("192.168.") or rip.startswith("10.") or rip.startswith("172.16.") or rip == "::1"):
                        external = True
                
                connections.append({
                    "local": laddr,
                    "remote": raddr,
                    "status": status,
                    "pid": pid,
                    "external": external
                })
            return jsonify({"connections": connections[:50]})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── Port Scanner ────────────────────────────────────────────────
    @app.route("/api/portscan", methods=["POST"])
    def run_port_scan_endpoint():
        data = request.get_json(silent=True)
        if not data or 'target' not in data:
            return jsonify({"error": "Missing target"}), 400
        
        target = data['target'].strip()
        if not target:
            return jsonify({"error": "Target required"}), 400
            
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC", 
            139: "NetBIOS", 443: "HTTPS", 445: "SMB", 
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
        }
        
        results = []
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({"error": "Could not resolve hostname"}), 400
            
        for port, service in common_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                state = "open"
            elif result in [10060, 11, 35]:
                state = "filtered"
            else:
                state = "closed"
            s.close()
            
            results.append({
                "port": port,
                "service": service,
                "state": state
            })
            
        return jsonify({"results": results})

    # ── Admin: Simulate Attacks ─────────────────────────────────────
    @app.route("/api/admin/simulate_attack", methods=["POST"])
    def simulate_attack():
        data = request.get_json(silent=True)
        if not data or 'type' not in data:
            return jsonify({"error": "Missing attack type"}), 400
            
        attack_type = data['type'].strip()
        
        timestamp = time.strftime("%H:%M:%S")
        
        if attack_type == "ddos":
            for _ in range(15):
                src_ip = f"185.220.101.{random.randint(1,254)}"
                pkt_info = {
                    "id": int(time.time() * 1000) % 100000 + random.randint(1,1000),
                    "timestamp": timestamp,
                    "source": src_ip,
                    "destination": "192.168.1.50",
                    "protocol": "TCP",
                    "suspicious": True,
                    "severity": "High",
                    "threat_type": "DDoS SYN Flood"
                }
                socketio.emit('new_packet', pkt_info)
            log_alert("simulator", "DDoS SYN Flood simulated", "High", "Simulation triggered by admin")
            socketio.emit('new_alert', {
                "timestamp": timestamp,
                "source": "185.220.101.X (Simulated)",
                "threat": "DDoS SYN Flood Attack",
                "severity": "High"
            })
            
        elif attack_type == "bruteforce":
            for i in range(3):
                log_alert("simulator", f"Failed SSH login attempt for user root from 203.0.113.88", "Medium")
            socketio.emit('new_alert', {
                "timestamp": timestamp,
                "source": "203.0.113.88",
                "threat": "SSH Brute Force Attempt",
                "severity": "Medium"
            })
            
        elif attack_type == "sqli":
            pkt_info = {
                "id": int(time.time() * 1000) % 100000,
                "timestamp": timestamp,
                "source": "45.227.254.10",
                "destination": "192.168.1.1",
                "protocol": "HTTP",
                "suspicious": True,
                "severity": "Critical",
                "threat_type": "SQL Injection Attempt"
            }
            socketio.emit('new_packet', pkt_info)
            log_alert("simulator", "SQL Injection simulated on web service", "Critical", "GET /api/users?id=1%20OR%201=1")
            socketio.emit('new_alert', {
                "timestamp": timestamp,
                "source": "45.227.254.10",
                "threat": "SQL Injection Detected",
                "severity": "Critical"
            })
            
        elif attack_type == "malware":
            pkt_info = {
                "id": int(time.time() * 1000) % 100000,
                "timestamp": timestamp,
                "source": "192.168.1.15",
                "destination": "198.51.100.77",
                "protocol": "TCP",
                "suspicious": True,
                "severity": "High",
                "threat_type": "C2 Callback Protocol"
            }
            socketio.emit('new_packet', pkt_info)
            log_alert("simulator", "Trojan beacon callback simulated", "High", "Connection to 198.51.100.77 on port 4444")
            socketio.emit('new_alert', {
                "timestamp": timestamp,
                "source": "192.168.1.15",
                "threat": "Malware C2 Beaconing",
                "severity": "High"
            })
            
        else:
            return jsonify({"error": "Unknown attack type"}), 400
            
        return jsonify({"success": True, "message": f"Simulation of {attack_type} initiated."})

    # ── Admin: IDS Rules ────────────────────────────────────────────
    @app.route("/api/admin/rules", methods=["GET"])
    def get_rules():
        return jsonify({"rules": active_rules})

    @app.route("/api/admin/rules", methods=["POST"])
    def save_rule():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Missing payload"}), 400
        
        rule_id = data.get("id")
        name = data.get("name", "").strip()
        match = data.get("match", "").strip()
        action = data.get("action", "block").strip()
        active = bool(data.get("active", True))

        if not name or not match:
            return jsonify({"error": "Rule name and match expression are required"}), 400

        if rule_id:
            # Update existing rule
            for rule in active_rules:
                if rule["id"] == int(rule_id):
                    rule["name"] = name
                    rule["match"] = match
                    rule["action"] = action
                    rule["active"] = active
                    log_alert("admin", f"IDS Rule Updated: {name}", "Low", f"Match: {match}, Action: {action}")
                    return jsonify({"success": True, "rules": active_rules})
            return jsonify({"error": "Rule not found"}), 404
        else:
            # Create new rule
            new_id = max([r["id"] for r in active_rules]) + 1 if active_rules else 1
            new_rule = {
                "id": new_id,
                "name": name,
                "match": match,
                "action": action,
                "active": active
            }
            active_rules.append(new_rule)
            log_alert("admin", f"New IDS Rule Created: {name}", "Low", f"Match: {match}, Action: {action}")
            return jsonify({"success": True, "rules": active_rules})

    @app.route("/api/admin/rules/toggle", methods=["POST"])
    def toggle_rule():
        data = request.get_json(silent=True)
        if not data or "id" not in data:
            return jsonify({"error": "Missing rule ID"}), 400
        
        rule_id = int(data["id"])
        is_active = bool(data.get("active", True))

        for rule in active_rules:
            if rule["id"] == rule_id:
                rule["active"] = is_active
                log_alert("admin", f"IDS Rule {'Enabled' if is_active else 'Disabled'}: {rule['name']}", "Low")
                return jsonify({"success": True, "rules": active_rules})
        return jsonify({"error": "Rule not found"}), 404

    @app.route("/api/admin/rules/<int:rule_id>", methods=["DELETE"])
    def delete_rule(rule_id):
        global active_rules
        for i, rule in enumerate(active_rules):
            if rule["id"] == rule_id:
                name = rule["name"]
                active_rules.pop(i)
                log_alert("admin", f"IDS Rule Deleted: {name}", "Low")
                return jsonify({"success": True, "rules": active_rules})
        return jsonify({"error": "Rule not found"}), 404

    # ── Admin: Reverse IP Trace ─────────────────────────────────────
    @app.route("/api/admin/trace", methods=["POST"])
    def trace_ip():
        data = request.get_json(silent=True)
        if not data or "ip" not in data:
            return jsonify({"error": "Missing IP parameter"}), 400
        
        ip = data["ip"].strip()
        if not ip:
            return jsonify({"error": "IP target is required"}), 400

        # Run simulated traceroute
        hops = [
            {"hop": 1, "ip": "192.168.1.1", "name": "local-gateway.home.arpa", "rtt": f"{random.uniform(0.5, 1.5):.2f} ms", "geo": "Local Subnet"},
            {"hop": 2, "ip": "10.45.192.1", "name": "isp-gateway-pool.net", "rtt": f"{random.uniform(3.0, 6.0):.2f} ms", "geo": "Regional Node"},
            {"hop": 3, "ip": "72.14.232.11", "name": "core-router-anycast.net", "rtt": f"{random.uniform(10.0, 15.0):.2f} ms", "geo": "State Exchange Center"},
            {"hop": 4, "ip": "142.250.230.15", "name": "border-edge-switch.google.com", "rtt": f"{random.uniform(22.0, 29.0):.2f} ms", "geo": "Carrier Backbone"},
            {"hop": 5, "ip": ip, "name": f"target-node-{ip.replace('.', '-')}", "rtt": f"{random.uniform(40.0, 65.0):.2f} ms", "geo": "Target Host"}
        ]
        
        log_alert("admin", f"Reverse IP Trace initiated: {ip}", "Low", f"Completed in 5 hops")
        return jsonify({
            "target": ip,
            "hops": hops,
            "asn": f"AS{random.randint(1000, 9999)}",
            "org": "Security Intelligence Services",
            "country": "United States",
            "city": "Dallas, Texas"
        })