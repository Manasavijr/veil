"""Tamper-evident audit log: each entry stores the SHA-256 of the previous entry (a hash chain).
Entries record what types were masked and counts, never the raw values."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("VEIL_DB_PATH", "veil.db")
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )"""
        )
        self.db.commit()

    @staticmethod
    def _digest(prev: str, ts: str, event: str) -> str:
        return hashlib.sha256(f"{prev}|{ts}|{event}".encode()).hexdigest()

    def append(self, event: dict) -> str:
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            ts = datetime.now(timezone.utc).isoformat()
            body = json.dumps(event, sort_keys=True, separators=(",", ":"))
            h = self._digest(prev, ts, body)
            self.db.execute("INSERT INTO audit(ts, event, prev_hash, hash) VALUES (?,?,?,?)", (ts, body, prev, h))
            self.db.commit()
            return h

    def verify(self) -> dict:
        prev = GENESIS
        n = 0
        for id_, ts, event, prev_hash, h in self.db.execute(
            "SELECT id, ts, event, prev_hash, hash FROM audit ORDER BY id"
        ):
            if prev_hash != prev or self._digest(prev, ts, event) != h:
                return {"ok": False, "entries": n, "broken_at_id": id_}
            prev, n = h, n + 1
        return {"ok": True, "entries": n, "head": prev}

    def tail(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT id, ts, event, hash FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": i, "ts": ts, "event": json.loads(e), "hash": h} for i, ts, e, h in rows]
