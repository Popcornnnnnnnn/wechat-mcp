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

"""Multi-shard connection pool and SQLite ATTACH / TEMP VIEW union engine."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
import re
import sqlite3
import threading
from typing import Dict, List, Optional, Set

logger = logging.getLogger("wechat_mcp.db.shards")


def md5_table(username: str) -> str:
    """Generate Msg_<hash> table name from talker username."""
    return "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()


class ShardManager:
    """Manages SQLite connections attached to all message_*.db shards.

    Constructs TEMP VIEW unions with '_shard' column tag to enable
    seamless querying across annual shards while eliminating connection leaks.
    """

    def __init__(self, message_dir: Path | str):
        self.message_dir = Path(message_dir)
        self._lock = threading.RLock()
        self._connection: Optional[sqlite3.Connection] = None
        self._shards: List[Path] = []
        self._table_shards: Dict[str, List[str]] = {}

    @property
    def lock(self) -> threading.RLock:
        """Thread synchronization lock for shared connection operations."""
        return self._lock

    def discover_shards(self) -> List[Path]:
        """Discover sorted message_0.db ... message_N.db files."""
        if not self.message_dir.exists():
            return []

        candidates = []
        for p in self.message_dir.glob("message_*.db"):
            m = re.fullmatch(r"message_([0-9]+)\.db", p.name)
            if m and not p.is_symlink():
                candidates.append((int(m.group(1)), p))

        candidates.sort(key=lambda x: x[0])
        return [p for _, p in candidates]

    def _init_connection(self) -> sqlite3.Connection:
        """Create and configure pooled SQLite connection with attached shards."""
        shards = self.discover_shards()
        if not shards:
            raise FileNotFoundError(f"No message shards found in {self.message_dir}")

        self._shards = shards
        main_shard = shards[0]
        # Open in read-only URI mode to prevent journal/wal creation on main shard
        conn = sqlite3.connect(
            f"file:{main_shard.resolve().as_posix()}?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row

        schemas = ["main"]
        for idx, shard_path in enumerate(shards[1:], start=1):
            schema_name = f"shard_{idx}"
            try:
                conn.execute(
                    f"ATTACH DATABASE 'file:{shard_path.resolve().as_posix()}?mode=ro' AS {schema_name};"
                )
                schemas.append(schema_name)
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                err_msg = str(e).lower()
                if "too many attached databases" in err_msg:
                    logger.warning("Reached SQLite attached database limit at shard_%d: %s", idx, e)
                    break
                if "file is not a database" in err_msg or "malformed" in err_msg or "corrupt" in err_msg:
                    logger.warning("Skipping corrupted non-SQLite shard %s: %s", shard_path, e)
                    continue
                raise

        # Discover all Msg_% tables across schemas
        table_owners: Dict[str, List[str]] = {}
        for schema in schemas:
            try:
                cur = conn.execute(
                    f"SELECT name FROM {schema}.sqlite_master WHERE type='table' AND name LIKE 'Msg_%';"
                )
                for row in cur.fetchall():
                    tname = row[0]
                    table_owners.setdefault(tname, []).append(schema)
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                logger.warning("Error discovering tables in schema %s: %s", schema, e)
                pass

        self._table_shards = table_owners

        # Build TEMP VIEW for each table with _shard column
        for tname, owner_schemas in table_owners.items():
            selects = [
                f"SELECT *, '{s}' AS _shard FROM {s}.\"{tname}\""
                for s in owner_schemas
            ]
            union_sql = " UNION ALL ".join(selects)
            # Create both v_{tname} and {tname} view for maximum compatibility
            conn.execute(f'CREATE TEMP VIEW IF NOT EXISTS "v_{tname}" AS {union_sql};')
            conn.execute(f'CREATE TEMP VIEW IF NOT EXISTS "{tname}" AS {union_sql};')

        try:
            conn.execute("PRAGMA query_only = ON;")
        except Exception:
            pass

        return conn

    def get_connection(self) -> sqlite3.Connection:
        """Get or initialize thread-safe pooled connection."""
        with self._lock:
            current_shards = self.discover_shards()
            if self._connection is None or current_shards != self._shards:
                self._close_internal()
                self._connection = self._init_connection()
            return self._connection

    def list_chat_tables(self) -> List[str]:
        """Return all distinct Msg_<hash> table names across all shards."""
        with self._lock:
            if not self.discover_shards():
                return []
            self.get_connection()
            return sorted(self._table_shards.keys())

    def table_exists(self, table_name: str) -> bool:
        """Check if conversation table exists in any shard."""
        with self._lock:
            if not self.discover_shards():
                return False
            self.get_connection()
            # Clean prefix if v_ was passed
            raw_name = table_name[2:] if table_name.startswith("v_") else table_name
            return raw_name in self._table_shards

    def _close_internal(self) -> None:
        """Internal close without acquiring lock (caller must hold lock)."""
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
            self._shards = []
            self._table_shards = {}

    def close(self) -> None:
        """Close connection and release file descriptors."""
        with self._lock:
            self._close_internal()
