import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnix.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        auth_provider TEXT NOT NULL DEFAULT 'local',
        google_sub TEXT
    )
    """)

    columns = {row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()}
    if "auth_provider" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'")
    if "google_sub" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        machine_name TEXT,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        scan_mode TEXT,
        status TEXT NOT NULL DEFAULT 'scanning',
        result_json TEXT,
        error_message TEXT,
        created_at TEXT NOT NULL,
        completed_at TEXT
    )
    """)

    columns = {row[1] for row in cursor.execute("PRAGMA table_info(scans)").fetchall()}
    if "machine_name" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN machine_name TEXT")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
