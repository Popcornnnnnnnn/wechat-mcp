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

"""Anti-recall watcher and dual-signal message preservation archive."""
from __future__ import annotations

import logging
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Union
import xml.etree.ElementTree as ET

from wechat_mcp.db.reader import HistoryReader

logger = logging.getLogger("wechat_mcp.watcher.recall")

TYPE_SYSMSG = 10000
TYPE_REVOKE = 10002
TIP_MARKS = ("撤回", "recalled a message", "revokemsg")


class RecallArchive:
    """
    Dual-signal Anti-Recall Watcher & Archive.
    Signal 1: Revoke tip messages (SysMsg / revokemsg XML).
    Signal 2: Vanished message bodies (diff against pre-indexed snapshot).
    """

    def __init__(
        self,
        db_dir: Union[str, Path],
        archive_path: Optional[Union[str, Path]] = None,
        reader: Optional[Any] = None,
    ):
        self.db_dir = Path(db_dir).resolve()
        if reader is not None:
            self.reader = reader
        else:
            self.reader = HistoryReader(self.db_dir)

        self.archive_path = (
            Path(archive_path).resolve()
            if archive_path
            else (self.db_dir / "recall-archive.sqlite")
        )
        self._indexed_msgs: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self._archived_server_ids: Set[int] = set()
        self._processed_tip_ids: Set[int] = set()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize archive SQLite database and schema."""
        self.archive_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.archive_path) as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS recalls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER UNIQUE,
                    session TEXT NOT NULL,
                    sender TEXT,
                    content TEXT,
                    recalled_at INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    media_path TEXT,
                    sender_wxid TEXT,
                    chatroom_id TEXT,
                    seq INTEGER,
                    created_at INTEGER,
                    detected_at INTEGER
                )
                """
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_recalls_session ON recalls(session);")
            db.execute("CREATE INDEX IF NOT EXISTS idx_recalls_recalled_at ON recalls(recalled_at);")
            db.execute("CREATE INDEX IF NOT EXISTS idx_recalls_source ON recalls(source);")
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_tips (
                    tip_server_id INTEGER PRIMARY KEY
                )
                """
            )
            db.commit()

            # Pre-load archived server_ids
            cur = db.execute("SELECT server_id FROM recalls WHERE server_id IS NOT NULL")
            self._archived_server_ids = {r[0] for r in cur.fetchall()}

            # Pre-load processed tip server_ids
            cur = db.execute("SELECT tip_server_id FROM processed_tips WHERE tip_server_id IS NOT NULL")
            self._processed_tip_ids = {r[0] for r in cur.fetchall()}

    def index_current_messages(self, session: str) -> None:
        """Pre-index current messages for diff-based detection."""
        data = self.reader.get_messages(session, limit=1000)
        msgs = data.get("messages", []) if isinstance(data, dict) else []
        self._indexed_msgs[session] = {
            m["server_id"]: m for m in msgs if m.get("server_id")
        }

    def _is_recalled(self, server_id: Optional[int]) -> bool:
        if server_id is None:
            return False
        return server_id in self._archived_server_ids

    def _parse_revoke_tip(self, content: str) -> Dict[str, Any]:
        """Parse revoke XML or plain text tip with regex fallback."""
        res: Dict[str, Any] = {
            "is_revoke": False,
            "session": None,
            "newmsgid": None,
            "replacemsg": None,
        }
        if not content or not isinstance(content, str):
            return res

        if "<revokemsg>" in content or "<sysmsg" in content:
            try:
                root = ET.fromstring(content)
                revokemsg = None
                if root.tag == "sysmsg":
                    revokemsg = root.find("revokemsg")
                elif root.tag == "revokemsg":
                    revokemsg = root

                if revokemsg is not None:
                    res["is_revoke"] = True
                    sess = revokemsg.find("session")
                    if sess is not None and sess.text:
                        res["session"] = sess.text
                    mid = revokemsg.find("newmsgid")
                    if mid is None:
                        mid = revokemsg.find("msgid")
                    if mid is not None and mid.text:
                        try:
                            res["newmsgid"] = int(mid.text)
                        except ValueError:
                            pass
                    repl = revokemsg.find("replacemsg")
                    if repl is not None and repl.text:
                        res["replacemsg"] = repl.text
                    return res
                else:
                    return res
            except Exception:
                pass

            # Regex fallback for malformed XML: only if revoke markers exist
            if (
                "<revokemsg>" in content
                or 'type="revokemsg"' in content
                or any(mark in content for mark in TIP_MARKS)
            ):
                res["is_revoke"] = True
                sess_m = re.search(r"<session>([^<]+)</session>", content)
                if sess_m:
                    res["session"] = sess_m.group(1)
                mid_m = re.search(r"<(?:newmsgid|msgid)>(\d+)</(?:newmsgid|msgid)>", content)
                if mid_m:
                    try:
                        res["newmsgid"] = int(mid_m.group(1))
                    except ValueError:
                        pass
                repl_m = re.search(
                    r"<replacemsg>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</replacemsg>", content
                )
                if repl_m:
                    res["replacemsg"] = repl_m.group(1)
                return res
            return res

        if any(mark in content for mark in TIP_MARKS):
            res["is_revoke"] = True
            res["replacemsg"] = content
            return res

        return res

    @staticmethod
    def _extract_media_path(content: str) -> Optional[str]:
        if not content or not isinstance(content, str):
            return None
        m = re.search(r'(?:cdnurl|thumburl|cdnthumburl|path|attachid)="([^"]+)"', content)
        if m:
            return m.group(1)
        m = re.search(r"<(?:file|path|url)>([^<]+)</(?:file|path|url)>", content)
        if m:
            return m.group(1)
        if content.startswith(("/", "file://", "C:", "~")):
            return content.strip()
        return None

    def scan(self, session: Optional[str] = None) -> List[Dict[str, Any]]:
        """Dual-signal scan: tip matching (Signal 1) + vanished diff (Signal 2)."""
        if session is not None:
            return self._scan_session(session)

        # If no session specified, scan all known sessions
        detected: List[Dict[str, Any]] = []
        chats = self.reader.list_chats()
        chat_list = chats.get("chats", chats) if isinstance(chats, dict) else chats
        for c in chat_list:
            sess_name = (
                c.get("username") or c.get("session")
                if isinstance(c, dict)
                else str(c)
            )
            if sess_name:
                detected.extend(self._scan_session(sess_name))
        return detected

    def _scan_session(self, session: str) -> List[Dict[str, Any]]:
        detected: List[Dict[str, Any]] = []
        current_data = self.reader.get_messages(session, limit=1000)
        current_msgs = (
            current_data.get("messages", []) if isinstance(current_data, dict) else []
        )
        curr_map = {m["server_id"]: m for m in current_msgs if m.get("server_id")}

        # Signal 1: SysMsg tip detection
        for m in current_msgs:
            m_type = m.get("type", 0)
            if m_type not in (TYPE_SYSMSG, TYPE_REVOKE):
                continue

            m_content = m.get("content", "")
            tip_info = self._parse_revoke_tip(m_content)

            if m_type == TYPE_REVOKE or tip_info["is_revoke"]:
                tip_sid = m.get("server_id")
                if tip_sid and tip_sid in self._processed_tip_ids:
                    continue

                target = None
                # Exact match via newmsgid if present
                if tip_info["newmsgid"]:
                    target = curr_map.get(tip_info["newmsgid"])
                    if not target and session in self._indexed_msgs:
                        target = self._indexed_msgs[session].get(tip_info["newmsgid"])

                # Fallback: preceding message before tip timestamp (only when newmsgid is absent)
                if target is None and not tip_info["newmsgid"]:
                    tip_time = m.get("create_time", 0)
                    prev_msgs = [
                        x
                        for x in current_msgs
                        if 0 <= (tip_time - x.get("create_time", 0)) <= 300
                        and x.get("type") not in (TYPE_SYSMSG, TYPE_REVOKE)
                        and x.get("server_id") != m.get("server_id")
                        and not self._is_recalled(x.get("server_id"))
                    ]
                    if prev_msgs:
                        target = prev_msgs[-1]
                    elif session in self._indexed_msgs:
                        prev_indexed = [
                            x
                            for x in self._indexed_msgs[session].values()
                            if 0 <= (tip_time - x.get("create_time", 0)) <= 300
                            and x.get("type") not in (TYPE_SYSMSG, TYPE_REVOKE)
                            and x.get("server_id") != m.get("server_id")
                            and not self._is_recalled(x.get("server_id"))
                        ]
                        if prev_indexed:
                            target = sorted(
                                prev_indexed,
                                key=lambda x: (
                                    x.get("create_time", 0),
                                    x.get("local_id", 0),
                                ),
                            )[-1]

                if target is not None:
                    sid = target.get("server_id")
                    if sid and not self._is_recalled(sid):
                        rec = {
                            "server_id": sid,
                            "session": session,
                            "sender": target.get("sender", ""),
                            "sender_wxid": target.get("sender_wxid") or target.get("sender", ""),
                            "chatroom_id": session if "@chatroom" in session else None,
                            "content": target.get("content", ""),
                            "media_path": self._extract_media_path(target.get("content", "")),
                            "recalled_at": m.get("create_time", int(time.time())),
                            "source": "tip",
                            "seq": target.get("local_id") or target.get("sort_seq") or 0,
                            "created_at": target.get("create_time"),
                            "detected_at": int(time.time()),
                        }
                        detected.append(rec)
                        self._persist_recall(rec)
                    if tip_sid:
                        self._persist_processed_tip(tip_sid)

        # Signal 2: Vanished diff detection
        if session in self._indexed_msgs:
            old_map = self._indexed_msgs[session]
            # Safety guard: prevent treating entire emptied database as mass recall
            if len(curr_map) == 0 and len(old_map) > 0:
                logger.warning(
                    "Session %s messages were completely cleared; skipping mass recall diff",
                    session,
                )
                self._indexed_msgs[session] = curr_map
                return detected

            is_sliding_window = len(current_msgs) >= 1000 or len(old_map) >= 1000
            valid_times = [
                m.get("create_time", 0)
                for m in current_msgs
                if m.get("create_time", 0) > 0
            ]
            min_curr_time = min(valid_times) if valid_times else 0

            for sid, old_m in old_map.items():
                if sid not in curr_map and old_m.get("type") not in (TYPE_SYSMSG, TYPE_REVOKE):
                    if is_sliding_window and old_m.get("create_time", 0) < min_curr_time:
                        continue
                    if not self._is_recalled(sid):
                        rec = {
                            "server_id": sid,
                            "session": session,
                            "sender": old_m.get("sender", ""),
                            "sender_wxid": old_m.get("sender_wxid") or old_m.get("sender", ""),
                            "chatroom_id": session if "@chatroom" in session else None,
                            "content": old_m.get("content", ""),
                            "media_path": self._extract_media_path(old_m.get("content", "")),
                            "recalled_at": int(time.time()),
                            "source": "diff",
                            "seq": old_m.get("local_id") or old_m.get("sort_seq") or 0,
                            "created_at": old_m.get("create_time"),
                            "detected_at": int(time.time()),
                        }
                        detected.append(rec)
                        self._persist_recall(rec)

        self._indexed_msgs[session] = curr_map
        return detected

    def _persist_recall(self, rec: Dict[str, Any]) -> None:
        """Persist recall record to SQLite database. OperationalError propagates."""
        with sqlite3.connect(self.archive_path) as db:
            db.execute(
                """
                INSERT OR IGNORE INTO recalls(
                    server_id, session, sender, content, recalled_at, source,
                    media_path, sender_wxid, chatroom_id, seq, created_at, detected_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.get("server_id"),
                    rec.get("session"),
                    rec.get("sender"),
                    rec.get("content"),
                    rec.get("recalled_at"),
                    rec.get("source"),
                    rec.get("media_path"),
                    rec.get("sender_wxid") or rec.get("sender"),
                    rec.get("chatroom_id")
                    or (
                        rec.get("session")
                        if "@chatroom" in str(rec.get("session", ""))
                        else None
                    ),
                    rec.get("seq", 0),
                    rec.get("created_at"),
                    rec.get("detected_at"),
                ),
            )
            db.commit()
            if rec.get("server_id"):
                self._archived_server_ids.add(rec["server_id"])

    def _persist_processed_tip(self, tip_server_id: int) -> None:
        """Record processed tip server_id to SQLite database."""
        if not tip_server_id:
            return
        self._processed_tip_ids.add(tip_server_id)
        with sqlite3.connect(self.archive_path) as db:
            db.execute(
                "INSERT OR IGNORE INTO processed_tips(tip_server_id) VALUES(?)",
                (tip_server_id,),
            )
            db.commit()

    def list_recalls(
        self,
        limit: int = 50,
        chatroom: Optional[str] = None,
        session: Optional[str] = None,
        since: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List preserved recalled messages."""
        target_session = chatroom or session
        with sqlite3.connect(self.archive_path) as db:
            sql = (
                "SELECT server_id, session, sender, content, recalled_at, source, "
                "media_path, sender_wxid, chatroom_id, seq FROM recalls"
            )
            params: List[Any] = []
            where: List[str] = []
            if target_session:
                where.append("(session = ? OR chatroom_id = ?)")
                params.extend([target_session, target_session])
            if since is not None:
                where.append("recalled_at >= ?")
                params.append(since)
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY recalled_at DESC, id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur = db.execute(sql, params)
            return [
                {
                    "server_id": r[0],
                    "session": r[1],
                    "sender": r[2],
                    "content": r[3],
                    "recalled_at": r[4],
                    "source": r[5],
                    "media_path": r[6],
                    "sender_wxid": r[7],
                    "chatroom_id": r[8],
                    "seq": r[9],
                }
                for r in cur.fetchall()
            ]

    def get_recall_stats(self) -> Dict[str, Any]:
        """Return recall archive statistics."""
        with sqlite3.connect(self.archive_path) as db:
            total = db.execute("SELECT COUNT(*) FROM recalls").fetchone()[0]
            tip = db.execute("SELECT COUNT(*) FROM recalls WHERE source='tip'").fetchone()[0]
            diff = db.execute("SELECT COUNT(*) FROM recalls WHERE source='diff'").fetchone()[0]
            indexed_count = sum(len(m) for m in self._indexed_msgs.values())
            return {
                "total": total,
                "tip": tip,
                "diff": diff,
                "total_recalls": total,
                "indexed_messages": indexed_count,
                "signals": {"tip": tip, "diff": diff},
            }


ReferenceRecallArchive = RecallArchive
