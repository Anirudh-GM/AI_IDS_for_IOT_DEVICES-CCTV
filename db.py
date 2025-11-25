import sqlite3
import os

DB_PATH = os.path.join(os.getcwd(), "ids_logs.db")

def init_db():
    """Initialize the database and create the logs table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            ts_readable TEXT,
            device TEXT,
            intrusion_type TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def insert_log(device, intrusion_type, timestamp, ts_readable):
    """Insert a new log entry into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (timestamp, ts_readable, device, intrusion_type)
        VALUES (?, ?, ?, ?)
    """, (timestamp, ts_readable, device, intrusion_type))
    conn.commit()
    conn.close()

def fetch_logs(limit=50):
    """Fetch recent log entries."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM logs ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows
