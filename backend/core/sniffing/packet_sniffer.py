from scapy.all import sniff, IP, TCP, UDP
import time
import threading
from config.settings import settings
from core.state import active_config, blocked_ips, active_rules

MAX_PACKETS = settings.MAX_PACKETS_TO_KEEP
recent_packets = []
connection_tracker = {}

def matches_rule(match_str, pkt_info):
    try:
        # Normalize and split by 'and'
        clauses = [c.strip() for c in match_str.lower().split("and")]
        for clause in clauses:
            if "==" in clause:
                key, val = [x.strip() for x in clause.split("==")]
                val = val.replace("'", "").replace('"', "")
                
                if key in ["dst_port", "port"]:
                    if str(pkt_info.get("dst_port")) != val:
                        return False
                elif key in ["src_ip", "src"]:
                    if pkt_info.get("source") != val:
                        return False
                elif key in ["dst_ip", "dst"]:
                    if pkt_info.get("destination") != val:
                        return False
                elif key in ["protocol", "proto"]:
                    if pkt_info.get("protocol").lower() != val:
                        return False
                elif key == "flags":
                    if pkt_info.get("flags", "").lower() != val:
                        return False
                else:
                    return False
            else:
                return False
        return True
    except Exception:
        return False

def evaluate_rules(pkt_info):
    # 1. Emergency lockdown check
    if active_config.get("emergency_lockdown", False):
        src = pkt_info.get("source", "")
        # Check if external IP
        is_external = not (src.startswith("127.") or src.startswith("192.168.") or src.startswith("10.") or src.startswith("172.16.") or src == "::1")
        if is_external:
            return True, "Critical", "FIREWALL LOCKDOWN BLOCK"

    # 2. Check blocklist first (highest priority)
    if pkt_info.get("source") in blocked_ips:
        return True, "High", "FIREWALL BLOCKED IP"

    # 3. Check IDS Rules in order
    for rule in active_rules:
        if not rule.get("active", False):
            continue
        
        match_expr = rule.get("match", "")
        if matches_rule(match_expr, pkt_info):
            action = rule.get("action", "block")
            if action == "block":
                return True, "High", f"IDS BLOCK: {rule['name']}"
            elif action == "alert-only":
                return True, "Medium", f"IDS ALERT: {rule['name']}"
            elif action == "allow":
                return False, "Low", None # Allowed, bypass other checks

    # 4. Standard Heuristics (Fallback if no rules match)
    if pkt_info.get("protocol") == "TCP" and pkt_info.get("flags") == "S":
        return True, "Medium", "Potential SYN Scan"

    return False, "Low", None

def analyze_packet(packet, socketio):
    global recent_packets

    if active_config.get("sniffing_paused", False):
        return

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "UDP" if UDP in packet else ("TCP" if TCP in packet else "OTHER")
            
            dst_port = None
            flags = ""
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif UDP in packet:
                dst_port = packet[UDP].dport
            
            # Temporary pkt_info for rule matching
            temp_pkt = {
                "source": src_ip,
                "destination": dst_ip,
                "protocol": proto,
                "dst_port": dst_port,
                "flags": flags
            }

            # Evaluate IDS rules
            is_suspicious, severity, threat_type = evaluate_rules(temp_pkt)

            # Heuristic tracker for DDoS rate limiting fallback
            if not is_suspicious:
                connection_tracker[src_ip] = connection_tracker.get(src_ip, 0) + 1
                if connection_tracker[src_ip] > 100: 
                    is_suspicious = True
                    severity = "High"
                    threat_type = "Rapid Requests / DoS attempt"
                    connection_tracker[src_ip] = 0

            pkt_info = {
                "id": int(time.time() * 1000) % 100000,
                "timestamp": time.strftime("%H:%M:%S"),
                "source": src_ip,
                "destination": dst_ip,
                "protocol": proto,
                "dst_port": dst_port,
                "flags": flags,
                "suspicious": is_suspicious,
                "severity": severity,
                "threat_type": threat_type
            }

            recent_packets.insert(0, pkt_info)
            if len(recent_packets) > MAX_PACKETS:
                recent_packets.pop()
            
            socketio.emit('new_packet', pkt_info)
            
            if is_suspicious:
                socketio.emit('new_alert', {
                    "timestamp": pkt_info['timestamp'],
                    "source": src_ip,
                    "threat": threat_type,
                    "severity": severity
                })

    except Exception as e:
        pass

def simulate_packets(socketio):
    import random
    fake_sources = [
        "192.168.1.15", "10.0.0.4", "192.168.1.100", "8.8.8.8", "1.1.1.1", 
        "185.220.101.5", "45.227.254.10", "198.51.100.77", "203.0.113.15"
    ]
    fake_dests = [
        "192.168.1.1", "10.0.0.1", "192.168.1.254", "172.16.0.5", 
        "192.168.1.50", "192.168.1.51", "192.168.1.52"
    ]
    protocols = ["TCP", "UDP", "OTHER"]
    
    threat_types = [
        ("Nmap Port Scan", "Medium", 80, "S"),
        ("SQL Injection Attempt", "High", 80, ""),
        ("SSH Brute Force", "Medium", 22, "PA"),
        ("Reverse Shell Activity", "High", 4444, "PA"),
        ("Malware C2 Ping", "High", 8080, "PA"),
        ("DDoS SYN Flood", "High", 80, "S")
    ]
    
    while True:
        if not active_config.get("sniffing_paused", False):
            socketio.sleep(random.uniform(1.0, 2.5))
            
            src = random.choice(fake_sources)
            dst = random.choice(fake_dests)
            proto = random.choice(protocols)
            dst_port = random.choice([80, 443, 22, 21, 53, 4444, 8080])
            flags = "S" if proto == "TCP" and random.random() < 0.2 else ""
            
            # Temporary pkt_info for rule matching
            temp_pkt = {
                "source": src,
                "destination": dst,
                "protocol": proto,
                "dst_port": dst_port,
                "flags": flags
            }
            
            # Evaluate rules
            is_suspicious, severity, threat_type = evaluate_rules(temp_pkt)
            
            # If no rule triggered, add random synthetic anomalies
            if not is_suspicious and random.random() < 0.15:
                threat_name, severity, dst_port, flags = random.choice(threat_types)
                is_suspicious = True
                threat_type = threat_name
                if threat_name == "Nmap Port Scan" or threat_name == "DDoS SYN Flood":
                    proto = "TCP"
                
            pkt_info = {
                "id": int(time.time() * 1000) % 100000,
                "timestamp": time.strftime("%H:%M:%S"),
                "source": src,
                "destination": dst,
                "protocol": proto,
                "dst_port": dst_port,
                "flags": flags,
                "suspicious": is_suspicious,
                "severity": severity,
                "threat_type": threat_type
            }
            
            recent_packets.insert(0, pkt_info)
            if len(recent_packets) > MAX_PACKETS:
                recent_packets.pop()
                
            socketio.emit('new_packet', pkt_info)
            
            if is_suspicious:
                socketio.emit('new_alert', {
                    "timestamp": pkt_info['timestamp'],
                    "source": src,
                    "threat": threat_type,
                    "severity": severity
                })
        else:
            socketio.sleep(1)

def packet_capture_loop(socketio):
    print("Starting scapy background packet capture...")
    try:
        sniff(prn=lambda pkt: analyze_packet(pkt, socketio), store=0)
    except Exception as e:
        print(f"Failed to start scapy packet sniffer: {e}")
        socketio.emit('admin_alert', {"message": "Packet sniffer failed to start."})

def start_sniffing(socketio):
    # Use Socket.IO's framework-agnostic background task manager
    socketio.start_background_task(target=packet_capture_loop, socketio=socketio)
    socketio.start_background_task(target=simulate_packets, socketio=socketio)
