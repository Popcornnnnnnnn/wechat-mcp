# Copyright (C) 2026 wechat-mcp contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Durable SQLite event store for WeChat message events."""
from __future__ import annotations

import json
import logging
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("wechat_mcp.watcher.journal")


class EventJournal:
    """
    Durable EventJournal implementing SQLite monotonic event logging per PROJECT.md §F6.
    
    Features:
    - Strictly monotonic autoincrementing sequence numbers (`seq`).
    - Cursor-based draining (`drain(cursor, limit)`).
    - Group chatroom filtering.
    - Transactional persistence in SQLite WAL mode.
    - Transient database lock retry with exponential backoff.
    - Safe additive schema evolution.
    - MCP resource head & group introspection.
    """

    def __init__(
        self,
        db_path: Union[str, Path],
        busy_timeout_ms: int = 5000,
        max_retries: int = 5,
    ):
        self.db_path = Path(db_path).resolve()
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.max_retries = int(max_retries)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a fresh SQLite connection with WAL mode and busy timeout configured."""
        conn = sqlite3.connect(self.db_path, timeout=self.busy_timeout_ms / 1000.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms};")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self) -> None:
        """Initialize database directory, tables, and indices."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_journal (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    chatroom_id TEXT NOT NULL,
                    sender_id TEXT,
                    msg_id INTEGER,
                    payload TEXT NOT NULL,
                    metadata TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_journal_chatroom ON event_journal(chatroom_id, seq);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_journal_seq ON event_journal(seq);"
            )
            conn.commit()

    def append(
        self,
        event_type: str,
        chatroom_id: str,
        payload: Union[str, Dict[str, Any]],
        sender_id: Optional[str] = None,
        msg_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Append an event to the journal and return the monotonic sequence number."""
        payload_str = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else str(payload)
        meta_str = json.dumps(metadata, ensure_ascii=False) if metadata else None
        now = time.time()

        for attempt in range(self.max_retries):
            try:
                with self._get_connection() as conn:
                    cur = conn.execute(
                        """
                        INSERT INTO event_journal (timestamp, event_type, chatroom_id, sender_id, msg_id, payload, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (now, event_type, chatroom_id, sender_id, msg_id, payload_str, meta_str),
                    )
                    conn.commit()
                    return cur.lastrowid
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < self.max_retries - 1:
                    time.sleep(0.01 * (2 ** attempt))
                    continue
                raise

    def append_batch(self, events: List[Dict[str, Any]]) -> List[int]:
        """Atomically append a batch of events within a single transaction."""
        now = time.time()
        for attempt in range(self.max_retries):
            try:
                seqs: List[int] = []
                with self._get_connection() as conn:
                    for ev in events:
                        p_val = ev.get("payload", "")
                        payload_str = json.dumps(p_val, ensure_ascii=False) if isinstance(p_val, (dict, list)) else str(p_val)
                        m_val = ev.get("metadata")
                        meta_str = json.dumps(m_val, ensure_ascii=False) if m_val else None
                        cur = conn.execute(
                            """
                            INSERT INTO event_journal (timestamp, event_type, chatroom_id, sender_id, msg_id, payload, metadata)
                            VALUES (?, ?, ?, ?, ?, ?, ?);
                            """,
                            (
                                now,
                                ev["event_type"],
                                ev["chatroom_id"],
                                ev.get("sender_id"),
                                ev.get("msg_id"),
                                payload_str,
                                meta_str,
                            ),
                        )
                        seqs.append(cur.lastrowid)
                    conn.commit()
                return seqs
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < self.max_retries - 1:
                    time.sleep(0.01 * (2 ** attempt))
                    continue
                raise

    def drain(
        self,
        since_seq: Optional[Union[int, str]] = None,
        limit: int = 100,
        chatroom_id: Optional[str] = None,
        cursor: Optional[Union[int, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Drain events with seq > cursor (or since_seq), optionally filtered by chatroom.
        Clamps invalid or negative sequence numbers cleanly to 0.
        """
        raw_cursor = cursor if cursor is not None else since_seq
        try:
            effective_since = int(raw_cursor) if raw_cursor is not None else 0
        except (ValueError, TypeError):
            effective_since = 0
        effective_since = max(0, effective_since)

        query = (
            "SELECT seq, timestamp, event_type, chatroom_id, sender_id, msg_id, payload, metadata "
            "FROM event_journal WHERE seq > ?"
        )
        params: List[Any] = [effective_since]
        if chatroom_id:
            query += " AND chatroom_id = ?"
            params.append(chatroom_id)
        query += " ORDER BY seq ASC LIMIT ?"
        params.append(max(1, int(limit)))

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
            results = []
            for r in rows:
                p_raw = r[6]
                try:
                    payload = json.loads(p_raw)
                except Exception:
                    payload = p_raw
                meta = None
                if r[7]:
                    try:
                        meta = json.loads(r[7])
                    except Exception:
                        meta = r[7]
                results.append({
                    "seq": r[0],
                    "timestamp": r[1],
                    "event_type": r[2],
                    "chatroom_id": r[3],
                    "sender_id": r[4],
                    "msg_id": r[5],
                    "payload": payload,
                    "metadata": meta,
                })
            return results

    def head(self, chatroom_id: Optional[str] = None) -> Dict[str, Any]:
        """Return head sequence and change token for MCP resource protocol."""
        query = "SELECT MAX(seq) FROM event_journal"
        params: List[Any] = []
        if chatroom_id:
            query += " WHERE chatroom_id = ?"
            params.append(chatroom_id)

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            row = cur.fetchone()
            max_seq = row[0] if (row and row[0] is not None) else 0
            return {
                "group": chatroom_id or "all",
                "change_token": f"token_{max_seq}",
                "head_cursor": str(max_seq),
            }

    @property
    def groups(self) -> List[str]:
        """Return list of distinct chatroom IDs with recorded events."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT DISTINCT chatroom_id FROM event_journal WHERE chatroom_id IS NOT NULL AND chatroom_id != '';")
            return [r[0] for r in cur.fetchall()]

    def migrate_schema(self) -> None:
        """Safely ensure all expected columns and indices exist on older databases."""
        with self._get_connection() as conn:
            cur = conn.execute("PRAGMA table_info(event_journal);")
            cols = {row[1] for row in cur.fetchall()}
            if "metadata" not in cols:
                conn.execute("ALTER TABLE event_journal ADD COLUMN metadata TEXT;")
            if "sender_id" not in cols:
                conn.execute("ALTER TABLE event_journal ADD COLUMN sender_id TEXT;")
            if "msg_id" not in cols:
                conn.execute("ALTER TABLE event_journal ADD COLUMN msg_id INTEGER;")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_journal_chatroom ON event_journal(chatroom_id, seq);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_journal_seq ON event_journal(seq);")
            conn.commit()


ReferenceEventJournal = EventJournal
