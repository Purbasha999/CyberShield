"""SQLite storage for security events and the file-integrity baseline."""

import json
import sqlite3
import threading
import time

from security.events import SEVERITY_RANK

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  REAL    NOT NULL,
    module     TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    rank       INTEGER NOT NULL,
    title      TEXT    NOT NULL,
    details    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);

CREATE TABLE IF NOT EXISTS file_baseline (
    path       TEXT PRIMARY KEY,
    root       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    mtime      REAL NOT NULL,
    mode       INTEGER NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_baseline_root ON file_baseline(root);

CREATE TABLE IF NOT EXISTS watch_roots (
    root       TEXT PRIMARY KEY,
    created_at REAL NOT NULL
);
"""


class EventDatabase:
    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()

    # ---- events -------------------------------------------------------

    def insert_event(self, event):
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (timestamp, module, severity, rank, title, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event.timestamp,
                    event.module,
                    event.severity,
                    SEVERITY_RANK[event.severity],
                    event.title,
                    json.dumps(event.details, default=str),
                ),
            )
            self._conn.commit()

    def recent_events(self, limit=50, min_severity="INFO", module=None, since=None):
        sql = "SELECT * FROM events WHERE rank >= ?"
        args = [SEVERITY_RANK[min_severity]]
        if module:
            sql += " AND module = ?"
            args.append(module)
        if since is not None:
            sql += " AND timestamp >= ?"
            args.append(since)
        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "module": r["module"],
                "severity": r["severity"],
                "title": r["title"],
                "details": json.loads(r["details"]),
            }
            for r in rows
        ]

    def severity_counts(self, since=None):
        since = since if since is not None else 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM events WHERE timestamp >= ? GROUP BY severity",
                (since,),
            ).fetchall()
        counts = {s: 0 for s in SEVERITY_RANK}
        counts.update({r["severity"]: r["n"] for r in rows})
        return counts

    def hourly_counts(self, hours=24, now=None):
        """Alert counts (LOW and above) per hour bucket, oldest bucket first."""
        now = now if now is not None else time.time()
        current_hour = int(now // 3600) * 3600
        start = current_hour - (hours - 1) * 3600
        with self._lock:
            rows = self._conn.execute(
                "SELECT CAST(timestamp / 3600 AS INTEGER) * 3600 AS bucket, severity, COUNT(*) AS n "
                "FROM events WHERE timestamp >= ? AND rank >= 1 GROUP BY bucket, severity",
                (start,),
            ).fetchall()
        buckets = [
            {"hour": start + i * 3600, "LOW": 0, "MEDIUM": 0, "HIGH": 0} for i in range(hours)
        ]
        for r in rows:
            index = (r["bucket"] - start) // 3600
            if 0 <= index < hours:
                buckets[index][r["severity"]] += r["n"]
        return buckets

    # ---- file baseline ------------------------------------------------

    def has_root(self, root):
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM watch_roots WHERE root = ?", (root,)).fetchone()
        return row is not None

    def add_root(self, root):
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO watch_roots (root, created_at) VALUES (?, ?)", (root, time.time())
            )
            self._conn.commit()

    def get_baseline(self, root):
        with self._lock:
            rows = self._conn.execute(
                "SELECT path, sha256, size, mtime, mode FROM file_baseline WHERE root = ?", (root,)
            ).fetchall()
        return {r["path"]: dict(r) for r in rows}

    def save_baseline(self, root, entries):
        """Replace the stored baseline of `root` with `entries` ({path: {sha256,size,mtime,mode}})."""
        now = time.time()
        with self._lock:
            self._conn.execute("DELETE FROM file_baseline WHERE root = ?", (root,))
            self._conn.executemany(
                "INSERT OR REPLACE INTO file_baseline (path, root, sha256, size, mtime, mode, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (path, root, e["sha256"], e["size"], e["mtime"], e["mode"], now)
                    for path, e in entries.items()
                ],
            )
            self._conn.commit()

    def upsert_file(self, root, path, entry):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO file_baseline (path, root, sha256, size, mtime, mode, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (path, root, entry["sha256"], entry["size"], entry["mtime"], entry["mode"], time.time()),
            )
            self._conn.commit()

    def delete_file(self, path):
        with self._lock:
            self._conn.execute("DELETE FROM file_baseline WHERE path = ?", (path,))
            self._conn.commit()

    def clear_baseline(self):
        with self._lock:
            self._conn.execute("DELETE FROM file_baseline")
            self._conn.execute("DELETE FROM watch_roots")
            self._conn.commit()
