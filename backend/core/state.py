# In-memory configuration states managed by the Admin Panel

active_config = {
    "sniffing_paused": False,
    "ai_enabled": True,
    "emergency_lockdown": False,
    "honeypot_active": True,
    "reverse_tracing_active": False,
    "db_encryption_active": False
}

blocked_ips = set()

active_rules = [
    {"id": 1, "name": "Block Metasploit Default Port", "match": "dst_port == 4444", "action": "block", "active": True},
    {"id": 2, "name": "Alert on SYN Scan Activity", "match": "protocol == TCP", "action": "alert-only", "active": True},
    {"id": 3, "name": "Allow Local Loopback traffic", "match": "src_ip == 127.0.0.1", "action": "allow", "active": True},
    {"id": 4, "name": "Block Malicious Test IP", "match": "src_ip == 203.0.113.15", "action": "block", "active": True},
    {"id": 5, "name": "Alert on DNS Anomalous payload", "match": "protocol == UDP", "action": "alert-only", "active": False},
]

