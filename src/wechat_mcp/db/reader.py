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

"""High-performance, bounded HistoryReader query engine implementing the unified database contract."""
from __future__ import annotations

import contextlib
import datetime
import logging
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Union

from wechat_mcp.db.decompress import decompress_content
from wechat_mcp.db.sender import SenderResolver
from wechat_mcp.db.shards import ShardManager, md5_table

logger = logging.getLogger("wechat_mcp.db.reader")

MSG_TYPE_NAMES: Dict[int, str] = {
    1: "文本",
    3: "图片",
    34: "语音",
    42: "名片",
    43: "视频",
    47: "表情",
    48: "位置",
    49: "链接/文件",
    50: "语音通话",
    51: "状态",
    10000: "系统",
    10002: "撤回",
}


def fmt_time(ts: Optional[int]) -> Optional[str]:
    """Format unix epoch timestamp to readable string."""
    if not ts:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


class HistoryReader:
    """Unified query engine for WeChat decrypted databases.

    Satisfies FastMCP 40 tools, FastAPI REST endpoints, and watcher queries
    across multi-shard SQLite structures without connection leaks.
    """

    def __init__(
        self,
        db_dir: Union[str, Path],
        syncer: Optional[Callable[[], Any]] = None,
    ):
        self.db_dir = Path(db_dir)
        self.syncer = syncer
        self.msg_dir = self.db_dir / "message"
        self.contact_db = self.db_dir / "contact" / "contact.db"
        self.session_db = self.db_dir / "session" / "session.db"
        self.shards = ShardManager(self.msg_dir)
        self.sender = SenderResolver(self.db_dir)
        self._lock = threading.RLock()

    def refresh(self) -> Dict[str, Any]:
        """Trigger sync callback and invalidate cached connections and resolvers."""
        with self.shards._lock:
            if self.syncer:
                try:
                    self.syncer()
                except Exception as e:
                    logger.error("Syncer execution failed: %s", e)
            self.shards.close()
            self.sender.reload()
            return {"status": "ok", "refreshed_at": int(time.time())}

    # Alias for legacy core protocol
    sync_history = refresh

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics across chats, messages, and contacts."""
        with self.shards._lock:
            # 1. Contacts count
            contacts_count = 0
            if self.contact_db.exists():
                try:
                    with contextlib.closing(
                        sqlite3.connect(
                            f"file:{self.contact_db.resolve().as_posix()}?mode=ro", uri=True
                        )
                    ) as db:
                        row = db.execute("SELECT COUNT(*) FROM contact;").fetchone()
                        contacts_count = row[0] if row else 0
                except Exception as e:
                    logger.debug("Failed counting contacts: %s", e)

            # 2. Chats count from session.db or message shards
            chats_count = 0
            if self.session_db.exists():
                try:
                    with contextlib.closing(
                        sqlite3.connect(
                            f"file:{self.session_db.resolve().as_posix()}?mode=ro", uri=True
                        )
                    ) as db:
                        row = db.execute("SELECT COUNT(*) FROM SessionTable;").fetchone()
                        chats_count = row[0] if row else 0
                except Exception as e:
                    logger.debug("Failed counting sessions: %s", e)

            discovered_shards = self.shards.discover_shards()
            if not discovered_shards:
                return {
                    "chats": chats_count,
                    "messages": 0,
                    "contacts": contacts_count,
                    "from": 0,
                    "to": int(time.time()),
                    "shard_count": 0,
                }

            chat_tables = self.shards.list_chat_tables()
            if chats_count == 0:
                chats_count = len(chat_tables)

            # 3. Messages count and time span
            total_messages = 0
            timestamps: List[int] = []

            if discovered_shards:
                try:
                    conn = self.shards.get_connection()
                    # Check TimeStamp tables
                    schemas = ["main"] + [f"shard_{i}" for i in range(1, len(discovered_shards))]
                    for schema in schemas:
                        try:
                            ts_row = conn.execute(
                                f"SELECT timestamp FROM {schema}.TimeStamp LIMIT 1;"
                            ).fetchone()
                            if ts_row and ts_row[0]:
                                timestamps.append(ts_row[0])
                        except sqlite3.OperationalError:
                            pass

                    # Count messages across all chat views
                    for tname in chat_tables:
                        try:
                            row = conn.execute(f'SELECT COUNT(*) FROM "v_{tname}";').fetchone()
                            if row:
                                total_messages += row[0]
                        except sqlite3.OperationalError:
                            pass
                except Exception as e:
                    logger.debug("Error computing message stats: %s", e)

            from_ts = min(timestamps) if timestamps else 0
            to_ts = max(timestamps) if timestamps else int(time.time())

            return {
                "chats": chats_count,
                "messages": total_messages,
                "contacts": contacts_count,
                "from": from_ts,
                "to": to_ts,
                "shard_count": len(discovered_shards),
            }

    # Alias for legacy core protocol
    stats = get_stats

    def list_chats(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List active chat sessions with pagination, ordered by latest timestamp."""
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        results: List[Dict[str, Any]] = []
        with self.shards._lock:
            if self.session_db.exists():
                try:
                    with contextlib.closing(
                        sqlite3.connect(
                            f"file:{self.session_db.resolve().as_posix()}?mode=ro", uri=True
                        )
                    ) as db:
                        db.row_factory = sqlite3.Row
                        cur = db.execute(
                            """
                            SELECT username, type, unread_count, summary, last_timestamp, last_msg_sender
                            FROM SessionTable
                            ORDER BY last_timestamp DESC
                            LIMIT ? OFFSET ?;
                            """,
                            (limit, offset),
                        )
                        for r in cur.fetchall():
                            uname = r["username"]
                            display = self.sender.resolve_display_name(uname)
                            results.append(
                                {
                                    "username": uname,
                                    "display_name": display,
                                    "is_group": uname.endswith("@chatroom") if uname else False,
                                    "type": r["type"],
                                    "unread_count": r["unread_count"],
                                    "summary": r["summary"],
                                    "last_timestamp": r["last_timestamp"],
                                    "last_msg_sender": r["last_msg_sender"],
                                }
                            )
                        return results
                except Exception as e:
                    logger.debug("Error listing sessions from session.db: %s", e)

            # Fallback to chat tables if session.db is not present
            chat_tables = self.shards.list_chat_tables()
            if chat_tables:
                conn = self.shards.get_connection()
                for tname in chat_tables[offset : offset + limit]:
                    try:
                        r = conn.execute(
                            f'SELECT COUNT(*) as n, MAX(create_time) as last_time FROM "v_{tname}";'
                        ).fetchone()
                        count = r["n"] if r else 0
                        last_time = r["last_time"] if r and r["last_time"] else 0
                        results.append(
                            {
                                "username": tname,
                                "display_name": tname,
                                "is_group": False,
                                "type": 1,
                                "unread_count": 0,
                                "summary": "",
                                "last_timestamp": last_time,
                                "last_msg_sender": "",
                                "count": count,
                            }
                        )
                    except Exception:
                        pass
                results.sort(key=lambda x: x["last_timestamp"], reverse=True)

            return results

    # Alias for legacy core protocol
    sessions = list_chats

    def get_messages(
        self,
        username: str,
        limit: int = 100,
        offset: int = 0,
        since_time: Optional[int] = None,
        since_id: int = 0,
        type_: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Fetch messages for a conversation across all shards via TEMP VIEW union."""
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        tname = md5_table(username)

        empty_result: Dict[str, Any] = {
            "messages": [],
            "count": 0,
            "total": 0,
            "offset": offset,
            "limit": limit,
            "next_since_id": since_id,
            "username": username,
        }

        with self.shards._lock:
            if not self.shards.table_exists(tname):
                return empty_result

            try:
                conn = self.shards.get_connection()
            except Exception:
                return empty_result

            where_clauses = []
            params: List[Any] = []

            if since_time is not None:
                where_clauses.append("create_time >= ?")
                params.append(since_time)

            if since_id > 0:
                where_clauses.append("server_id > ?")
                params.append(since_id)

            if type_ is not None:
                where_clauses.append("(local_type & 0xFFFFFFFF) = ?")
                params.append(type_)

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            # Count total
            try:
                count_cur = conn.execute(f'SELECT COUNT(*) FROM "v_{tname}" {where_sql};', params)
                total_count = count_cur.fetchone()[0]
            except Exception as e:
                logger.debug("Error querying message count: %s", e)
                return empty_result

            # Fetch page
            query = f"""
                SELECT local_id, server_id, local_type, sort_seq, real_sender_id,
                       create_time, status, source, message_content, compress_content,
                       WCDB_CT_message_content, _shard
                FROM "v_{tname}"
                {where_sql}
                ORDER BY create_time ASC, sort_seq ASC
                LIMIT ? OFFSET ?;
            """
            try:
                rows = conn.execute(query, (*params, limit, offset)).fetchall()
            except Exception as e:
                logger.debug("Error querying messages: %s", e)
                return empty_result

            messages = []
            max_server_id = since_id
            for r in rows:
                sid = r["server_id"] or 0
                if sid > max_server_id:
                    max_server_id = sid

                raw_shard = r["_shard"] if ("_shard" in r.keys() and r["_shard"]) else None
                shard_tag = raw_shard or "main"
                real_sender = r["real_sender_id"] or 0
                sender_wxid, sender_name = self.sender.resolve(shard_tag, real_sender)

                wc_ct = r["WCDB_CT_message_content"] if "WCDB_CT_message_content" in r.keys() else None
                text = decompress_content(
                    r["message_content"], wc_ct, r["compress_content"]
                )

                raw_type = r["local_type"] or 0
                base_type = raw_type & 0xFFFFFFFF if raw_type > 0xFFFFFFFF else raw_type
                sub_type = (raw_type >> 32) & 0xFFFFFFFF if raw_type > 0xFFFFFFFF else 0

                messages.append(
                    {
                        "local_id": r["local_id"],
                        "server_id": sid,
                        "type": base_type,
                        "sub_type": sub_type,
                        "type_name": MSG_TYPE_NAMES.get(base_type, f"类型{base_type}"),
                        "create_time": r["create_time"],
                        "time": fmt_time(r["create_time"]),
                        "ts": r["create_time"],
                        "sender": sender_name,
                        "sender_wxid": sender_wxid,
                        "content": text,
                        "status": r["status"],
                        "shard": shard_tag,
                    }
                )

            return {
                "messages": messages,
                "count": len(messages),
                "total": total_count,
                "offset": offset,
                "limit": limit,
                "next_since_id": max_server_id,
                "username": username,
            }

    # Alias for legacy core protocol
    messages = get_messages

    def search_messages(
        self,
        query: str,
        limit: int = 50,
        session: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Bounded search across chat conversations and decompressed content."""
        limit = max(1, min(limit, 1000))
        if not query or not query.strip():
            return []

        with self.shards._lock:
            try:
                conn = self.shards.get_connection()
            except Exception:
                return []

            results: List[Dict[str, Any]] = []

            if session:
                tname = md5_table(session)
                target_tables = [tname] if self.shards.table_exists(tname) else []
            else:
                target_tables = self.shards.list_chat_tables()

            query_lower = query.lower()
            for tname in target_tables:
                try:
                    cur = conn.execute(
                        f"""
                        SELECT local_id, server_id, local_type, create_time, message_content,
                               compress_content, WCDB_CT_message_content, _shard, real_sender_id
                        FROM "v_{tname}"
                        ORDER BY create_time DESC
                        LIMIT 500;
                        """
                    )
                    for r in cur.fetchall():
                        wc_ct = (
                            r["WCDB_CT_message_content"]
                            if "WCDB_CT_message_content" in r.keys()
                            else None
                        )
                        content = decompress_content(
                            r["message_content"], wc_ct, r["compress_content"]
                        )
                        if query_lower in content.lower():
                            raw_shard = r["_shard"] if ("_shard" in r.keys() and r["_shard"]) else None
                            shard_tag = raw_shard or "main"
                            sender_wxid, sender_name = self.sender.resolve(
                                shard_tag, r["real_sender_id"] or 0
                            )
                            raw_type = r["local_type"] or 0
                            base_type = raw_type & 0xFFFFFFFF if raw_type > 0xFFFFFFFF else raw_type

                            results.append(
                                {
                                    "table": tname,
                                    "local_id": r["local_id"],
                                    "server_id": r["server_id"],
                                    "type": base_type,
                                    "type_name": MSG_TYPE_NAMES.get(base_type, f"类型{base_type}"),
                                    "create_time": r["create_time"],
                                    "time": fmt_time(r["create_time"]),
                                    "content": content,
                                    "shard": shard_tag,
                                    "sender": sender_name,
                                    "sender_wxid": sender_wxid,
                                }
                            )
                            if len(results) >= limit:
                                return results
                except sqlite3.OperationalError:
                    continue

            return results

    # Aliases for legacy core protocol
    search = search_messages
    search_all = search_messages

    def list_contacts(
        self,
        query: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List and search contacts with literal LIKE pattern matching."""
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        if not self.contact_db.exists():
            return []

        results: List[Dict[str, Any]] = []
        with self._lock:
            try:
                with contextlib.closing(
                    sqlite3.connect(
                        f"file:{self.contact_db.resolve().as_posix()}?mode=ro", uri=True
                    )
                ) as db:
                    db.row_factory = sqlite3.Row
                    sql = "SELECT id, username, alias, remark, nick_name FROM contact"
                    params: List[Any] = []
                    if query:
                        # Escape %, _, \ for literal matching
                        escaped = (
                            query.replace("\\", "\\\\")
                            .replace("%", "\\%")
                            .replace("_", "\\_")
                        )
                        pattern = f"%{escaped}%"
                        sql += (
                            " WHERE username LIKE ? ESCAPE '\\' OR alias LIKE ? ESCAPE '\\' "
                            "OR remark LIKE ? ESCAPE '\\' OR nick_name LIKE ? ESCAPE '\\'"
                        )
                        params.extend([pattern, pattern, pattern, pattern])

                    sql += " ORDER BY username LIMIT ? OFFSET ?;"
                    params.extend([limit, offset])

                    cur = db.execute(sql, params)
                    for r in cur.fetchall():
                        results.append(
                            {
                                "id": r["id"],
                                "username": r["username"],
                                "alias": r["alias"],
                                "remark": r["remark"],
                                "nick_name": r["nick_name"],
                            }
                        )
            except Exception as e:
                logger.debug("Error querying contacts: %s", e)

            return results

    # Alias for legacy core protocol
    contacts = list_contacts
