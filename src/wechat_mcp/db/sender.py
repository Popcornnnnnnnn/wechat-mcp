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

"""Multi-shard sender resolution mapping (shard, real_sender_id) -> username -> contact directory."""
from __future__ import annotations

import contextlib
import logging
from pathlib import Path
import re
import sqlite3
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger("wechat_mcp.db.sender")


class SenderResolver:
    """Caches per-shard Name2Id mappings and contact.db directory.

    Resolves sender username and friendly display names cleanly without cross-shard collisions.
    """

    def __init__(self, db_root: Path | str):
        self.db_root = Path(db_root)
        self.contact_db = self.db_root / "contact" / "contact.db"
        self.msg_dir = self.db_root / "message"
        self._lock = threading.RLock()
        self._name2id_cache: Dict[str, Dict[int, str]] = {}
        self._contact_cache: Dict[str, Dict[str, str]] = {}
        self._loaded = False

    def reload(self) -> None:
        """Invalidate and reload caches."""
        with self._lock:
            self._name2id_cache.clear()
            self._contact_cache.clear()
            self._load_contacts()
            self._load_all_name2id()
            self._loaded = True

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.reload()

    def _load_contacts(self) -> None:
        if not self.contact_db.exists():
            return

        try:
            with contextlib.closing(
                sqlite3.connect(
                    f"file:{self.contact_db.resolve().as_posix()}?mode=ro", uri=True
                )
            ) as db:
                db.row_factory = sqlite3.Row
                cur = db.execute("SELECT username, nick_name, remark, alias FROM contact;")
                for r in cur.fetchall():
                    uname = r["username"]
                    if uname:
                        self._contact_cache[uname] = {
                            "nick_name": r["nick_name"] or "",
                            "remark": r["remark"] or "",
                            "alias": r["alias"] or "",
                        }
        except Exception as e:
            logger.debug("Failed to load contact.db: %s", e)

    def _load_all_name2id(self) -> None:
        if not self.msg_dir.exists():
            return

        # Find and sort message_*.db
        shards = []
        for p in self.msg_dir.glob("message_*.db"):
            m = re.fullmatch(r"message_([0-9]+)\.db", p.name)
            if m and not p.is_symlink():
                shards.append((int(m.group(1)), p))
        shards.sort(key=lambda x: x[0])

        for shard_idx, shard_file in shards:
            schema_key = "main" if shard_idx == 0 else f"shard_{shard_idx}"
            shard_mapping: Dict[int, str] = {}
            try:
                with contextlib.closing(
                    sqlite3.connect(
                        f"file:{shard_file.resolve().as_posix()}?mode=ro", uri=True
                    )
                ) as db:
                    cur = db.execute("SELECT rowid, user_name FROM Name2Id;")
                    for r in cur.fetchall():
                        shard_mapping[r[0]] = r[1]
            except sqlite3.OperationalError:
                pass  # Shard might not have Name2Id table
            except Exception as e:
                logger.debug("Error reading Name2Id from %s: %s", shard_file, e)

            # Map under both schema name ('main', 'shard_1') and filename ('message_0.db')
            self._name2id_cache[schema_key] = shard_mapping
            self._name2id_cache[shard_file.name] = shard_mapping

    def resolve_sender_wxid(self, shard_tag: Optional[str], real_sender_id: int) -> str:
        """Map (shard, real_sender_id) to wxid. Fallback to str(real_sender_id)."""
        self._ensure_loaded()
        if not shard_tag or not isinstance(shard_tag, str):
            shard_tag = "main"
        mapping = self._name2id_cache.get(shard_tag, {})
        # If not found directly, also try normalized keys
        if real_sender_id in mapping:
            return mapping[real_sender_id]

        # Check if shard_tag is a filename or schema
        for key in (shard_tag, shard_tag.replace("shard_", "message_") + ".db"):
            if key in self._name2id_cache and real_sender_id in self._name2id_cache[key]:
                return self._name2id_cache[key][real_sender_id]

        return str(real_sender_id)

    def resolve_display_name(self, username: str) -> str:
        """Resolve wxid to remark > nick_name > alias > username."""
        self._ensure_loaded()
        info = self._contact_cache.get(username)
        if not info:
            return username
        return info["remark"] or info["nick_name"] or info["alias"] or username

    def resolve(self, shard_tag: Optional[str], real_sender_id: int) -> Tuple[str, str]:
        """Return tuple of (sender_wxid, display_name)."""
        if not shard_tag or not isinstance(shard_tag, str):
            shard_tag = "main"
        wxid = self.resolve_sender_wxid(shard_tag, real_sender_id)
        display = self.resolve_display_name(wxid)
        return wxid, display
