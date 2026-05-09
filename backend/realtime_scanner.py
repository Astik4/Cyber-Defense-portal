import psutil
import time

def run_deep_scan(socketio):
    """
    Simulates a deep system scan over various active processes and ports,
    emitting progress to the frontend via WebSockets.
    """
    total_steps = 15
    threats_found = []
    
    # Send Start Signal
    socketio.emit('scan_progress', {"percent": 0, "status": "Initializing Deep System Scan Phase..."})
    time.sleep(1)

    for i in range(1, total_steps + 1):
        percent = int((i / total_steps) * 100)
        
        # 1. Inspect Active Processes
        if i == 3:
            status = "Scanning Active Processes Memory Signatures..."
            threat_count = 0
            for proc in psutil.process_iter(['name', 'exe', 'cpu_percent']):
                try:
                    if threat_count >= 2: break # Limit arbitrary findings for the dashboard demo

                    proc_info = proc.info
                    exe_path = proc_info.get('exe', '')
                    proc_name = proc_info.get('name', '')
                    cpu_perc = proc_info.get('cpu_percent', 0.0)

                    # Simulating heuristics for malicious files: running from temp, unexpected extensions
                    if exe_path and ('\\Temp\\' in exe_path or '\\AppData\\Local\\Temp\\' in exe_path):
                        if not any(safe_name in proc_name.lower() for safe_name in ['npm', 'node', 'python', 'runner']):
                            threats_found.append({
                                "name": f"Suspicious execution from Temp: {proc_name}",
                                "severity": "High",
                                "action": "Quarantine File & Kill Process"
                            })
                            threat_count +=1
                    
                    # Simulating high CPU usage by an unknown background process
                    elif cpu_perc > 80.0 and proc_name.lower() not in ['system idle process', 'system', 'chrome.exe', 'firefox.exe']:
                         threats_found.append({
                                "name": f"Abnormal CPU Spike by {proc_name} ({cpu_perc}%)",
                                "severity": "Medium",
                                "action": "Kill Process & Inspect Memory"
                            })
                         threat_count +=1

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        # 2. Inspect Network Sockets
        elif i == 8:
            status = "Inspecting Externally Facing Network Sockets..."
            threat_count = 0
            # Common suspicious ports used by malware/C2 (Simulated heuristic)
            suspicious_ports = [4444, 1337, 31337, 666, 6667] 
            
            for conn in psutil.net_connections(kind='inet'):
                if threat_count >= 2: break
                 
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port

                        # Ignore local loopback connections for the scan alert
                        if not r_ip.startswith('127.') and not r_ip.startswith('192.168.') and not r_ip.startswith('10.'):
                            if r_port in suspicious_ports:
                                threats_found.append({
                                    "name": f"High Risk Outbound Connection Active ({r_ip}:{r_port})",
                                    "severity": "Critical",
                                    "action": "Immediate Firewall Block & Isolate Host"
                                })
                                threat_count += 1
                            # Simulate finding an unusual high port
                            elif r_port > 60000:
                                # Only flag truly unusual high ports (60000+)
                                # Common browser/OS ephemeral ports are 49152-60000
                                threats_found.append({
                                    "name": f"Suspicious Ephemeral Port Connection ({r_ip}:{r_port})",
                                    "severity": "Low",
                                    "action": "Monitor — likely browser/OS traffic, verify if unexpected"
                                })
                                threat_count += 1
                    except Exception:
                        pass

        # 3. Analyze Startup Registry / Services (Simulated due to complex OS dependencies)
        elif i == 12:
            status = "Analyzing System Registry & Startup Triggers..."

        else:
            status = f"Analyzing segment block 0x{hex(i * 4567).upper()[2:]}..."

        # Update frontend
        socketio.emit('scan_progress', {"percent": percent, "status": status})
        
        # Send intermediate threats updates if new ones were found this loop
        if threats_found:
             socketio.emit('scan_threat', {"threats": threats_found})

        time.sleep(0.8) # Slight delay for visual progression effect
        
    final_score = 100 - (len(threats_found) * 12)
    final_score = max(0, final_score)
    
    return {
        "status": "Scan Complete",
        "threats": threats_found,
        "score": final_score
    }