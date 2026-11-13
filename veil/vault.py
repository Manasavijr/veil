"""Encrypted token vault: original values are stored Fernet-encrypted, looked up by keyed hash."""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading

from cryptography.fernet import Fernet


class Vault:
    def __init__(self, path: str | None = None, key: str | bytes | None = None):
        self.path = path or os.getenv("VEIL_DB_PATH", "veil.db")
        key = key or os.getenv("VEIL_VAULT_KEY")
        if not key:
            # Ephemeral key: fine for tests and demos, mappings won't survive a restart.
            key = Fernet.generate_key()
        self.key = key.encode() if isinstance(key, str) else key
        self.fernet = Fernet(self.key)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS tokens (
                session TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                original_enc BLOB NOT NULL,
                fake TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (session, original_hash)
            )"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_fake ON tokens(session, fake)")
        self.db.commit()

    def _h(self, session: str, original: str) -> str:
        return hmac.new(self.key, f"{session}\x00{original}".encode(), hashlib.sha256).hexdigest()

    def get_fake(self, session: str, original: str) -> str | None:
        row = self.db.execute(
            "SELECT fake FROM tokens WHERE session=? AND original_hash=?", (session, self._h(session, original))
        ).fetchone()
        return row[0] if row else None

    def fake_taken(self, session: str, fake: str) -> bool:
        return self.db.execute("SELECT 1 FROM tokens WHERE session=? AND fake=?", (session, fake)).fetchone() is not None

    def put(self, session: str, entity_type: str, original: str, fake: str) -> None:
        with self._lock:
            self.db.execute(
                "INSERT OR IGNORE INTO tokens(session, entity_type, original_hash, original_enc, fake) VALUES (?,?,?,?,?)",
                (session, entity_type, self._h(session, original), self.fernet.encrypt(original.encode()), fake),
            )
            self.db.commit()

    def reverse_map(self, session: str) -> dict[str, str]:
        """fake -> original, decrypted, for restoring model output."""
        rows = self.db.execute("SELECT fake, original_enc FROM tokens WHERE session=?", (session,)).fetchall()
        return {fake: self.fernet.decrypt(enc).decode() for fake, enc in rows}

    def purge(self, session: str) -> int:
        with self._lock:
            cur = self.db.execute("DELETE FROM tokens WHERE session=?", (session,))
            self.db.commit()
            return cur.rowcount
