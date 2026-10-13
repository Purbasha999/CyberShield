import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone


class EventLogger:
    def __init__(self, base_dir):
        self.lock = threading.Lock()
        self.log_dir = os.path.join(base_dir, "logs")
        self.db_dir = os.path.join(base_dir, "database")
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.db_dir, exist_ok=True)

        self.log_path = os.path.join(self.log_dir, "cybershield.log")
        self.db_path = os.path.join(self.db_dir, "cybershield.db")

        self.file_logger = logging.getLogger("CyberShield")
        self.file_logger.setLevel(logging.INFO)
        self.file_logger.handlers.clear()

        handler = logging.FileHandler(self.log_path)
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        self.file_logger.addHandler(handler)

        self.connection = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            )
            """
        )
        self.connection.commit()

    def log(self, source, severity, message, details=None):
        timestamp = datetime.now(timezone.utc).isoformat()
        details_text = json.dumps(details or {})

        with self.lock:
            self.file_logger.info(
                "%s | %s | %s | %s",
                source, severity, message, details_text
            )
            self.connection.execute(
                "INSERT INTO events(timestamp, source, severity, message, details) VALUES (?, ?, ?, ?, ?)",
                (timestamp, source, severity, message, details_text)
            )
            self.connection.commit()

    def recent_events(self, limit=100):
        with self.lock:
            cursor = self.connection.execute(
                "SELECT id, timestamp, source, severity, message, details "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()

        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "source": row[2],
                "severity": row[3],
                "message": row[4],
                "details": row[5]
            }
            for row in rows
        ]

    def close(self):
        with self.lock:
            self.connection.close()
