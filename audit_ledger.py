"""Persistent, single-host, hash-linked audit ledger backed by SQLite.

The chain is tamper-evident, not independently immutable: a privileged operator
who can rewrite the database can also recompute hashes. Export/anchor digests
outside this host when independent evidence is required.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_GENESIS = "0" * 64


class SQLiteAuditLedger:
    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS audit_events (
                    index_no INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )"""
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return connection

    @staticmethod
    def _canonical(event: dict[str, Any]) -> bytes:
        return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def append(self, event_type: str, details: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT index_no, event_hash FROM audit_events ORDER BY index_no DESC LIMIT 1"
            ).fetchone()
            index = (int(row["index_no"]) + 1) if row else 1
            previous_hash = str(row["event_hash"]) if row else _GENESIS
            event: dict[str, Any] = {
                "index": index,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": event_type,
                "details": details,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(self._canonical(event)).hexdigest()
            db.execute(
                "INSERT INTO audit_events(index_no, timestamp, event_type, details_json, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (index, event["timestamp"], event_type, json.dumps(details, sort_keys=True), previous_hash, event_hash),
            )
            return {**event, "hash": event_hash}

    def verify(self) -> bool:
        previous_hash = _GENESIS
        expected_index = 1
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_events ORDER BY index_no").fetchall()
        for row in rows:
            if row["index_no"] != expected_index or row["previous_hash"] != previous_hash:
                return False
            try:
                details = json.loads(row["details_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            event = {
                "index": int(row["index_no"]),
                "timestamp": row["timestamp"],
                "type": row["event_type"],
                "details": details,
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(self._canonical(event)).hexdigest()
            if calculated != row["event_hash"]:
                return False
            previous_hash = calculated
            expected_index += 1
        return True

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        bounded = min(max(int(limit), 1), 100)
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY index_no DESC LIMIT ?", (bounded,)
            ).fetchall()
        output = []
        for row in rows:
            output.append({
                "index": row["index_no"],
                "timestamp": row["timestamp"],
                "type": row["event_type"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "hash": row["event_hash"],
            })
        return output

    def checkpoint(self) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT index_no, event_hash, timestamp FROM audit_events ORDER BY index_no DESC LIMIT 1"
            ).fetchone()
        return {
            "format": "sentinel-audit-checkpoint-v1",
            "verified": self.verify(),
            "event_count": int(row["index_no"]) if row else 0,
            "head_hash": str(row["event_hash"]) if row else _GENESIS,
            "head_timestamp": row["timestamp"] if row else None,
            "note": "Export and retain this checkpoint outside the host for independent comparison; it is not signed by this service.",
        }
