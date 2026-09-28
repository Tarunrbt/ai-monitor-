"""
storage.py
Lightweight SQLite persistence layer. Keeps the agent dependency-free
(no external DB server needed) so it runs fine on Termux/Android or a server.
"""

import sqlite3
import time
import json
from contextlib import contextmanager


SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    cpu_percent REAL,
    mem_percent REAL,
    status TEXT,
    num_threads INTEGER,
    io_read_bytes INTEGER,
    io_write_bytes INTEGER
);

CREATE INDEX IF NOT EXISTS idx_samples_name_ts ON samples(name, ts);

CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    name TEXT NOT NULL,
    event TEXT NOT NULL,
    pid INTEGER,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    scope TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence TEXT
);

CREATE TABLE IF NOT EXISTS baselines (
    name TEXT NOT NULL,
    metric TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    mean REAL NOT NULL DEFAULT 0,
    m2 REAL NOT NULL DEFAULT 0,
    updated_ts REAL,
    PRIMARY KEY (name, metric)
);

CREATE TABLE IF NOT EXISTS alerts_sent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    scope TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    channel TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    scope TEXT NOT NULL,
    trigger TEXT NOT NULL,
    strategy TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT
);
"""


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            cols = [r[1] for r in conn.execute("PRAGMA table_info(alerts_sent)").fetchall()]
            if "dedup_key" not in cols:
                conn.execute("ALTER TABLE alerts_sent ADD COLUMN dedup_key TEXT NOT NULL DEFAULT ''")

    def insert_sample(self, s: dict):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO samples
                   (ts, pid, name, cpu_percent, mem_percent, status,
                    num_threads, io_read_bytes, io_write_bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (s["ts"], s["pid"], s["name"], s["cpu_percent"],
                 s["mem_percent"], s["status"], s["num_threads"],
                 s.get("io_read_bytes"), s.get("io_write_bytes")),
            )

    def insert_event(self, name: str, event: str, pid: int = None, detail: str = ""):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO process_events (ts, name, event, pid, detail) VALUES (?, ?, ?, ?, ?)",
                (time.time(), name, event, pid, detail),
            )

    def insert_suggestion(self, scope: str, severity: str, message: str, evidence: dict):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO suggestions (ts, scope, severity, message, evidence)
                   VALUES (?, ?, ?, ?, ?)""",
                (time.time(), scope, severity, message, json.dumps(evidence)),
            )

    def recent_samples(self, name: str, since_ts: float):
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT ts, cpu_percent, mem_percent FROM samples WHERE name=? AND ts>=? ORDER BY ts",
                (name, since_ts),
            )
            return cur.fetchall()

    def recent_suggestions(self, limit: int = 20):
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT ts, scope, severity, message FROM suggestions ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()

    def distinct_process_names(self, since_ts: float):
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT DISTINCT name FROM samples WHERE ts >= ?", (since_ts,)
            )
            return [r[0] for r in cur.fetchall()]

    def get_baseline(self, name: str, metric: str):
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT count, mean, m2 FROM baselines WHERE name=? AND metric=?",
                (name, metric),
            )
            row = cur.fetchone()
            return row

    def upsert_baseline(self, name: str, metric: str, count: int, mean: float, m2: float):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO baselines (name, metric, count, mean, m2, updated_ts)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name, metric) DO UPDATE SET
                     count=excluded.count, mean=excluded.mean, m2=excluded.m2,
                     updated_ts=excluded.updated_ts""",
                (name, metric, count, mean, m2, time.time()),
            )

    def last_alert_ts(self, scope: str, dedup_key: str) -> float:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT MAX(ts) FROM alerts_sent WHERE scope=? AND dedup_key=?",
                (scope, dedup_key),
            )
            row = cur.fetchone()
            return row[0] if row and row[0] else 0.0

    def log_alert(self, scope: str, severity: str, message: str, channel: str, dedup_key: str = ""):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO alerts_sent (ts, scope, severity, message, dedup_key, channel) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), scope, severity, message, dedup_key or message, channel),
            )

    def recovery_attempts_since(self, scope: str, since_ts: float) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM recovery_actions WHERE scope=? AND ts>=? AND outcome='success'",
                (scope, since_ts),
            )
            return cur.fetchone()[0]

    def last_recovery_ts(self, scope: str) -> float:
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT MAX(ts) FROM recovery_actions WHERE scope=?", (scope,)
            )
            row = cur.fetchone()
            return row[0] if row and row[0] else 0.0

    def log_recovery(self, scope: str, trigger: str, strategy: str, outcome: str, detail: str = ""):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO recovery_actions (ts, scope, trigger, strategy, outcome, detail)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (time.time(), scope, trigger, strategy, outcome, detail),
            )

    def recent_recovery_actions(self, limit: int = 20):
        with self._conn() as conn:
            cur = conn.execute(
                "SELECT ts, scope, strategy, outcome, detail FROM recovery_actions ORDER BY ts DESC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()
