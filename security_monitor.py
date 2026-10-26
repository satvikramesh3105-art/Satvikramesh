"""Persistent, defensive HTTP request monitoring for the Sentinel demo app.

This inspects application-visible HTTP requests only. It is not a packet sniffer,
network IDS, machine-learning detector, or substitute for an upstream DDoS service.
"""

from __future__ import annotations

import re
import ipaddress
import json
import math
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote_plus


_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "path-traversal",
        re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|/|\\))", re.IGNORECASE),
        "Path traversal pattern",
    ),
    (
        "sql-injection",
        re.compile(
            r"(?:\bunion\s+select\b|\bselect\b.{0,100}\bfrom\b|"
            r"(?:['\"]\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+)|"
            r"\b(?:drop|truncate)\s+table\b|--\s)",
            re.IGNORECASE,
        ),
        "SQL injection signature",
    ),
    (
        "xss",
        re.compile(r"(?:<\s*script\b|javascript\s*:|<\s*iframe\b|\bon\w+\s*=)", re.IGNORECASE),
        "Cross-site scripting signature",
    ),
    (
        "command-injection",
        re.compile(r"(?:[;|&]{1,2}\s*(?:cat|id|whoami|curl|wget|bash|sh|nc)\b|\$\([^)]{1,120}\))", re.IGNORECASE),
        "Command injection signature",
    ),
    (
        "scanner-probe",
        re.compile(r"(?:^|/)(?:\.git|\.env|wp-admin|phpmyadmin)(?:/|$)", re.IGNORECASE),
        "Common exposed-file or admin scan",
    ),
)


class RequestMonitor:
    """Record request metadata, detect basic HTTP attack signals, and apply TTL blocks."""

    def __init__(
        self,
        database: str | Path,
        *,
        rate_limit: int = 60,
        rate_window_seconds: int = 10,
        block_seconds: int = 60,
        anomaly_model: dict[str, Any] | None = None,
    ) -> None:
        self.database = str(database)
        self.rate_limit = max(1, int(rate_limit))
        self.rate_window_seconds = max(1, int(rate_window_seconds))
        self.block_seconds = max(1, int(block_seconds))
        self.anomaly_model = anomaly_model
        self._anomaly_scoring_lock = threading.Lock()
        self._maintenance_lock = threading.Lock()
        self._last_cleanup = 0.0
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS request_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    path TEXT NOT NULL,
                    action TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_request_hits_ip_time
                    ON request_hits(source_ip, occurred_at);
                CREATE INDEX IF NOT EXISTS idx_request_hits_time
                    ON request_hits(occurred_at);
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    summary TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_security_events_time
                    ON security_events(occurred_at);
                CREATE TABLE IF NOT EXISTS ip_blocks (
                    source_ip TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS anomaly_windows (
                    window_start INTEGER PRIMARY KEY,
                    score REAL NOT NULL,
                    features_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )
            hit_columns = {row["name"] for row in db.execute("PRAGMA table_info(request_hits)")}
            if "method" not in hit_columns:
                db.execute("ALTER TABLE request_hits ADD COLUMN method TEXT NOT NULL DEFAULT 'GET'")

    @staticmethod
    def classify(signal: str) -> tuple[str, str] | None:
        """Return a rule ID and explanation without retaining the inspected payload."""
        decoded = signal
        for _ in range(2):
            decoded = unquote_plus(decoded)
        for rule_id, pattern, explanation in _RULES:
            if pattern.search(decoded):
                return rule_id, explanation
        return None

    def _record_hit(self, db: sqlite3.Connection, now: float, ip: str, path: str, method: str, action: str) -> None:
        db.execute(
            "INSERT INTO request_hits (occurred_at, source_ip, path, action, method) VALUES (?, ?, ?, ?, ?)",
            (now, ip[:64], path[:240], action, method[:12]),
        )

    def _score_current_window(self, db: sqlite3.Connection, now: float) -> None:
        if self.anomaly_model is None:
            return
        bucket = int(now // self.rate_window_seconds)
        with self._anomaly_scoring_lock:
            if db.execute("SELECT 1 FROM anomaly_windows WHERE window_start = ?", (bucket,)).fetchone():
                return
            since = now - self.rate_window_seconds
            rows = db.execute(
                "SELECT source_ip, path, method, action FROM request_hits WHERE occurred_at >= ?",
                (since,),
            ).fetchall()
            if len(rows) < 2:
                return
            source_counts: dict[str, int] = {}
            route_counts: dict[str, int] = {}
            blocked = 0
            for row in rows:
                source_counts[row["source_ip"]] = source_counts.get(row["source_ip"], 0) + 1
                route_counts[row["path"]] = route_counts.get(row["path"], 0) + 1
                blocked += row["action"] == "blocked"
            source_entropy = -sum(
                (count / len(rows)) * math.log(count / len(rows))
                for count in source_counts.values()
            )
            suspicious_events = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE occurred_at >= ?", (since,)
            ).fetchone()[0]
            features = {
                "requests": float(len(rows)),
                "unique_sources": float(len(source_counts)),
                "unique_routes": float(len(route_counts)),
                "blocked_ratio": float(blocked / len(rows)),
                "suspicious_events": float(suspicious_events),
                "source_entropy": float(source_entropy),
            }
            from anomaly_model import score_window

            outcome = score_window(self.anomaly_model, features)
            db.execute(
                "INSERT INTO anomaly_windows(window_start, score, features_json, created_at) VALUES (?, ?, ?, ?)",
                (bucket, outcome["score"], json.dumps(features, sort_keys=True), now),
            )
            if outcome["anomaly"]:
                self._record_event(
                    db,
                    now,
                    "multiple-sources",
                    "*",
                    "<aggregate-window>",
                    "ml-anomaly",
                    "alert",
                    f"Isolation Forest outlier score {outcome['score']:.4f}; review traffic window.",
                )

    def _record_event(
        self,
        db: sqlite3.Connection,
        now: float,
        ip: str,
        method: str,
        path: str,
        rule: str,
        action: str,
        summary: str,
    ) -> None:
        db.execute(
            """INSERT INTO security_events
               (occurred_at, source_ip, method, path, rule, severity, action, summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, ip[:64], method[:12], path[:240], rule[:48], "high", action[:16], summary[:160]),
        )

    def inspect(
        self,
        *,
        source_ip: str,
        method: str,
        path: str,
        signal: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        timestamp = time.time() if now is None else now
        ip = (source_ip or "unknown")[:64]
        request_path = (path or "/")[:240]
        try:
            is_loopback = ipaddress.ip_address(ip).is_loopback
        except ValueError:
            is_loopback = False

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            block = db.execute(
                "SELECT expires_at, reason FROM ip_blocks WHERE source_ip = ?", (ip,)
            ).fetchone()
            if block and block["expires_at"] > timestamp:
                if not is_loopback:
                    self._record_hit(db, timestamp, ip, request_path, method, "blocked")
                    return {
                        "action": "blocked",
                        "status": 429,
                        "rule": block["reason"],
                        "retry_after": max(1, int(block["expires_at"] - timestamp)),
                    }
                # Keep the local dashboard reachable after testing a rule from localhost.
                db.execute("DELETE FROM ip_blocks WHERE source_ip = ?", (ip,))
            if block:
                db.execute("DELETE FROM ip_blocks WHERE source_ip = ?", (ip,))

            detection = self.classify(signal)
            if detection:
                rule_id, explanation = detection
                expires = timestamp + self.block_seconds
                if not is_loopback:
                    db.execute(
                        """INSERT INTO ip_blocks(source_ip, expires_at, reason) VALUES (?, ?, ?)
                           ON CONFLICT(source_ip) DO UPDATE SET expires_at=excluded.expires_at,
                           reason=excluded.reason""",
                        (ip, expires, rule_id),
                    )
                self._record_event(db, timestamp, ip, method, request_path, rule_id, "blocked", explanation)
                self._record_hit(db, timestamp, ip, request_path, method, "blocked")
                return {
                    "action": "blocked",
                    "status": 403,
                    "rule": rule_id,
                    "retry_after": self.block_seconds if not is_loopback else 0,
                }

            cutoff = timestamp - self.rate_window_seconds
            recent = db.execute(
                "SELECT COUNT(*) AS request_count FROM request_hits "
                "WHERE source_ip = ? AND occurred_at >= ? AND action = 'allowed'",
                (ip, cutoff),
            ).fetchone()["request_count"]
            if recent >= self.rate_limit and not is_loopback:
                expires = timestamp + self.block_seconds
                if not is_loopback:
                    db.execute(
                        """INSERT INTO ip_blocks(source_ip, expires_at, reason) VALUES (?, ?, 'request-rate')
                           ON CONFLICT(source_ip) DO UPDATE SET expires_at=excluded.expires_at,
                           reason=excluded.reason""",
                        (ip, expires),
                    )
                summary = f"More than {self.rate_limit} requests in {self.rate_window_seconds}s"
                self._record_event(db, timestamp, ip, method, request_path, "request-rate", "blocked", summary)
                self._record_hit(db, timestamp, ip, request_path, method, "blocked")
                return {
                    "action": "blocked",
                    "status": 429,
                    "rule": "request-rate",
                    "retry_after": self.block_seconds,
                }

            self._record_hit(db, timestamp, ip, request_path, method, "allowed")
            self._score_current_window(db, timestamp)

        if timestamp - self._last_cleanup > 600:
            with self._maintenance_lock:
                if timestamp - self._last_cleanup > 600:
                    try:
                        with self._connection() as db:
                            db.execute("DELETE FROM request_hits WHERE occurred_at < ?", (timestamp - 86400,))
                            db.execute("DELETE FROM ip_blocks WHERE expires_at <= ?", (timestamp,))
                            db.execute("DELETE FROM security_events WHERE occurred_at < ?", (timestamp - 90 * 86400,))
                        self._last_cleanup = timestamp
                    except sqlite3.Error:
                        # Request evaluation should not fail solely because optional cleanup failed.
                        pass
        return {"action": "allowed", "status": 200, "rule": None, "retry_after": 0}

    def metrics(self, *, now: float | None = None) -> dict[str, Any]:
        timestamp = time.time() if now is None else now
        with self._connection() as db:
            counts = db.execute(
                """SELECT
                    SUM(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END) AS requests_window,
                    SUM(CASE WHEN occurred_at >= ? THEN 1 ELSE 0 END) AS requests_hour,
                    SUM(CASE WHEN occurred_at >= ? AND action = 'blocked' THEN 1 ELSE 0 END) AS blocked_10m
                    FROM request_hits""",
                (timestamp - self.rate_window_seconds, timestamp - 3600, timestamp - 600),
            ).fetchone()
            active = db.execute("SELECT COUNT(*) FROM ip_blocks WHERE expires_at > ?", (timestamp,)).fetchone()[0]
            total_events = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            anomaly_alerts = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE rule = 'ml-anomaly' AND occurred_at >= ?",
                (timestamp - 600,),
            ).fetchone()[0]
        return {
            "requests_window": counts["requests_window"] or 0,
            "requests_hour": counts["requests_hour"] or 0,
            "blocked_10m": counts["blocked_10m"] or 0,
            "active_blocks": active,
            "total_events": total_events,
            "anomaly_alerts_10m": anomaly_alerts,
            "anomaly_model": self.anomaly_model.get("source") if self.anomaly_model else None,
            "rate_limit": self.rate_limit,
            "window_seconds": self.rate_window_seconds,
            "block_seconds": self.block_seconds,
            "inspection": "HTTP request metadata and JSON/form inputs",
        }

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        bounded_limit = min(max(int(limit), 1), 100)
        with self._connection() as db:
            rows = db.execute(
                """SELECT id, occurred_at, source_ip, method, path, rule, severity, action, summary
                   FROM security_events ORDER BY id DESC LIMIT ?""",
                (bounded_limit,),
            ).fetchall()
        return [dict(row) for row in rows]
