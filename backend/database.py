import sqlite3
from datetime import datetime
import os

DB_FILE = "cybershield.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_module TEXT,
            threat_name TEXT,
            severity TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_alert(source_module, threat_name, severity, details=""):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, source_module, threat_name, severity, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_module, threat_name, severity, details))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=50):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
