# 🛡️ CYBERSHIELD Enterprise SOC Portal

An end-to-end, enterprise-grade Security Operations Center (SOC) simulation platform featuring a modern command-and-control dashboard, real-time packet sniffing, reactive intrusion detection system (IDS) rules, diagnostics utilities, persistent event logs, and an AI-powered security threat analyzer.

Re-architected with a premium slate-grey design system, clear typography hierarchy, and a strict separation of administrative panel workflows and monitoring dashboards.

---

## 🚀 Key Features

* **📡 Real-Time Packet Sniffing**: Live packet capture stream with custom protocol analysis (TCP, UDP, ICMP) powered by a Scapy-based sniffer or an integrated simulation engine.
* **🔒 Standalone Secure Admin Interface**: Completely separated administrative routing (`/admin/login` and `/admin/panel`) with secure credentials and access controls.
* **🚨 Reactive IDS Engine**: Evaluates live packet payloads against active security rules. Supports custom rule sets with real-time logging.
* **⚡ Active Defense Control Grid**:
  * **Emergency Lockdown Mode**: Instantly drops all external network connections and blocks incoming requests from non-local subnet IPs.
  * **Honeypot Active Trap**: Lures anomalous requests into synthetic decoys.
  * **Dynamic IP Banning (Blocklist)**: Ban malicious IPs directly from the alert list or manage the blocklist dynamically.
  * **Database Encryption**: Enforces hardware-accelerated payload field isolation.
* **📊 Diagnostic & Threat Tools**:
  * **Interactive Visual Traceroute**: Generates node-by-node route traces showing hop latency, geological labels, and AS details.
  * **Multi-Port Scanner**: Audits open and filtered status of standard communication ports (FTP, SSH, DNS, HTTP, SMB, MySQL, etc.) for a target.
  * **Attack Simulator**: Safely triggers mock DDoS attacks, SQL injection patterns, malware C2 callout loops, and brute-force simulations.
* **🧠 AI-Assisted Threat Analysis**: Leverages Google Gemini models to assess potential attacks, providing immediate mitigation summaries.
* **💾 Persistent SQLite Storage**: Logs all historical alert streams, failed auth logins, system scans, and actions persistently.
* **📥 CSV Data Exporting**: Download snapshot lists of active buffers and logs in a clean spreadsheet format.

---

## 🛠️ Architecture & Tech Stack

### Frontend Structure
- **Framework**: SPA React client powered by `react-router-dom` (compiled on-the-fly via Babel).
- **Styling**: Curated Vanilla CSS using a premium dark slate color theme. Font systems are set to Inter, Plus Jakarta Sans, and JetBrains Mono.
- **WebSocket Client**: Real-time server-push connection via `socket.io-client`.

### Backend Service
- **Core Server**: Flask app served via Werkzeug and integrated with `flask-cors`.
- **WSGI / Sockets**: `flask-socketio` enabling asynchronous notification loops.
- **Sniffing Engine**: `scapy` with fallback thread generation for isolated sandbox environments.
- **Database Engine**: `sqlite3` for schema tracking and security log persistence.
- **System Metrics**: `psutil` providing live CPU, RAM, disk, and connection diagnostics.

---

## 📂 Project Structure

```
├── backend/
│   ├── api/
│   │   └── routes.py             # Auth, system stats, blocklist, traceroute, and rules CRUD routes
│   ├── config/
│   │   └── settings.py           # Environment variables loader
│   ├── core/
│   │   ├── analyzer/
│   │   │   └── ai_analyzer.py    # AI model prompt evaluation pipeline
│   │   ├── scanning/
│   │   │   └── realtime_scanner.py # Heuristic system port scanner
│   │   ├── sniffing/
│   │   │   └── packet_sniffer.py # Packet capture loop and rule validation engine
│   │   └── state.py              # In-memory config, rule lists, and blocklist set
│   ├── db/
│   │   └── database.py           # Database setup and CRUD logging operations
│   └── app.py                    # Server initiation point
├── frontend/
│   └── index.html                # Unified React GUI, routing, styling, and charts
├── .env                          # Local credentials configuration
├── .gitignore                    # Git file exclusions
└── README.md                     # Documentation
```

---

## ⚙️ Installation & Local Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Astik4/cyber-defense-portal.git
cd cyber-defense-portal
```

### 2. Configure the Environment
Create a `.env` file in the root directory:
```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=supershield
SECRET_KEY=cyber-defense-super-secret
PORT=5000
DEBUG=True

# (Optional) Enable AI Analyzer Widget
GEMINI_API_KEY=your_gemini_api_key_here
```

### 3. Install Dependencies
Ensure you have Python 3.9+ installed. Create a virtual environment and load packages:
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 4. Run the Platform
Start the backend flask server:
```bash
python backend/app.py
```
Open [http://localhost:5000/dashboard](http://localhost:5000/dashboard) to view the live dashboard.

---

## 🛡️ IDS Rule Grammar & Configuration

The Administrative Panel supports compiling custom matches on incoming packets. The rule engine validates rules written in standard expressions.

### Valid Match Keys:
* `src_ip` / `src`: Source IP address.
* `dst_ip` / `dst`: Destination IP address.
* `dst_port` / `port`: Target connection port.
* `protocol` / `proto`: Matches `TCP`, `UDP`, or `OTHER`.
* `flags`: TCP packet flag settings (`S` for SYN, `PA` for PUSH-ACK, etc.).

### Examples:
- **Block malicious source IP**: `src_ip == 203.0.113.15`
- **Drop incoming Traffic on target port**: `dst_port == 4444`
- **Alert on any TCP port scanning**: `protocol == TCP and flags == S`

---

## 👤 Login Credentials
* **Default Admin ID**: `admin`
* **Default Security Password**: `supershield`

*Warning: Ensure passwords are changed in production environments.*
