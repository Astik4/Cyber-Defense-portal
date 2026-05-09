from scapy.all import sniff, IP, TCP, UDP
import time
import threading
from config.settings import settings
from core.state import active_config, blocked_ips

MAX_PACKETS = settings.MAX_PACKETS_TO_KEEP
recent_packets = []
connection_tracker = {}

def analyze_packet(packet, socketio):
    global recent_packets

    if active_config.get("sniffing_paused", False):
        return

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "UDP" if UDP in packet else ("TCP" if TCP in packet else "OTHER")
            
            is_suspicious = False
            severity = "Low"
            threat_type = None

            # 1. Check Firewall Blocklist First (Admin Panel overrides)
            if src_ip in blocked_ips:
                is_suspicious = True
                severity = "High"
                threat_type = "FIREWALL BLOCKED IP"
            else:
                # 2. Heuristics
                if TCP in packet:
                    flags = packet[TCP].flags
                    if flags == "S": 
                        is_suspicious = True
                        severity = "Medium"
                        threat_type = "Potential SYN Scan"
                
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

def packet_capture_loop(socketio):
    print("Starting scapy background packet capture...")
    try:
        sniff(prn=lambda pkt: analyze_packet(pkt, socketio), store=0)
    except Exception as e:
        print(f"Failed to start scapy packet sniffer: {e}")
        socketio.emit('admin_alert', {"message": "Packet sniffer failed to start."})

def start_sniffing(socketio):
    capture_thread = threading.Thread(target=packet_capture_loop, args=(socketio,), daemon=True)
    capture_thread.start()
