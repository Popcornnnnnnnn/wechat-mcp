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

"""
Synthetic Multi-Shard WeChat SQLite Database Generator.

Generates realistic WeChat 4.x directory structures with:
- Temporal multi-shards: message_0.db through message_4.db (1-year epoch separation).
- Per-shard Name2Id table with implicit rowids.
- Msg_<md5(username)> conversation tables.
- Multiple message types: Text (Type 1), Image (Type 3), AppMsg links (Type 49),
  SysMsg / Revoke (Type 10000 / 10002).
- Compression variants: WCDB zstd (WCDB_CT_message_content=4), legacy zlib in compress_content,
  and uncompressed plain text.
- contact.db (contact, chat_room, chatroom_member, name2id).
- session.db (SessionTable, Name2Id).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import zlib

try:
    import zstandard
except ImportError:
    zstandard = None

from tests.fixtures.crypto_generator import (
    create_sqlite_db_with_reserve,
    encrypt_sqlite_db,
)

# Core message types
TYPE_TEXT: int = 1
TYPE_IMAGE: int = 3
TYPE_VOICE: int = 34
TYPE_APPMSG: int = 49
TYPE_SYSMSG: int = 10000
TYPE_REVOKE: int = 10002

# Sub-types
SUBTYPE_LINK: int = 5
SUBTYPE_FILE: int = 6
SUBTYPE_QUOTE: int = 57

# WCDB column compression flags
WCDB_CT_PLAIN: int = 0
WCDB_CT_ZSTD: int = 4

# Shard time interval: 1 year (365 days = 31,536,000 s)
YEAR_SECONDS: int = 31536000


def md5_table(username: str) -> str:
    """Derive Msg_<hex> table name from talker username."""
    return "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()


class SyntheticWeChatFixture:
    """
    Synthetic WeChat environment generator creating isolated mock database hierarchies.
    """

    def __init__(self, root_dir: Union[str, Path], base_time: Optional[int] = None):
        self.root = Path(root_dir)
        self.msg_dir = self.root / "message"
        self.contact_dir = self.root / "contact"
        self.session_dir = self.root / "session"
        for d in (self.msg_dir, self.contact_dir, self.session_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Default base time: 2026 epoch ~ 1787449317
        self.base_time = base_time or 1787449317

    def _compress_zstd(self, data: bytes) -> bytes:
        if zstandard:
            return zstandard.ZstdCompressor(level=3).compress(data)
        # Fallback if zstandard is somehow missing
        return b"\x28\xb5\x2f\xfd" + data

    def build_contact_db(
        self,
        contacts: List[Dict[str, Any]],
        chatrooms: Optional[List[Dict[str, Any]]] = None,
        with_reserve: bool = False,
    ) -> Path:
        """Create and populate contact.db."""
        chatrooms = chatrooms or []
        db_path = self.contact_dir / "contact.db"

        sql_schema = """
            CREATE TABLE contact(
                id INTEGER PRIMARY KEY,
                username TEXT,
                local_type INTEGER,
                alias TEXT,
                remark TEXT,
                nick_name TEXT,
                big_head_url TEXT,
                small_head_url TEXT
            );
            CREATE INDEX contact_localType ON contact(local_type);
            CREATE TABLE chat_room(
                id INTEGER PRIMARY KEY,
                username TEXT,
                owner TEXT,
                ext_buffer BLOB
            );
            CREATE TABLE chatroom_member(
                room_id INTEGER,
                member_id INTEGER,
                CONSTRAINT room_member UNIQUE(room_id, member_id)
            );
            CREATE TABLE name2id(username TEXT PRIMARY KEY);
        """

        if with_reserve:
            create_sqlite_db_with_reserve(db_path, sql_schema)
        else:
            with sqlite3.connect(db_path) as db:
                db.executescript(sql_schema)

        with sqlite3.connect(db_path) as db:
            all_users = set(c["username"] for c in contacts)
            for cr in chatrooms:
                all_users.add(cr["username"])
                all_users.update(cr.get("members", []))

            user_id_map: Dict[str, int] = {}
            for uid, uname in enumerate(sorted(all_users), start=1):
                db.execute("INSERT INTO name2id(rowid, username) VALUES(?, ?)", (uid, uname))
                user_id_map[uname] = uid

            for c in contacts:
                cid = user_id_map[c["username"]]
                db.execute(
                    "INSERT INTO contact(id, username, local_type, alias, remark, nick_name) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        cid,
                        c["username"],
                        c.get("local_type", 1),
                        c.get("alias", ""),
                        c.get("remark", ""),
                        c.get("nick_name", c["username"]),
                    ),
                )

            for cr in chatrooms:
                room_id = user_id_map[cr["username"]]
                db.execute(
                    "INSERT INTO chat_room(id, username, owner) VALUES(?, ?, ?)",
                    (room_id, cr["username"], cr.get("owner", "")),
                )
                for m in cr.get("members", []):
                    mem_id = user_id_map[m]
                    db.execute(
                        "INSERT INTO chatroom_member(room_id, member_id) VALUES(?, ?)",
                        (room_id, mem_id),
                    )
            db.commit()

        return db_path

    def build_session_db(
        self,
        sessions: List[Dict[str, Any]],
        with_reserve: bool = False,
    ) -> Path:
        """Create and populate session.db."""
        db_path = self.session_dir / "session.db"

        sql_schema = """
            CREATE TABLE SessionTable(
                username TEXT PRIMARY KEY,
                type INTEGER,
                unread_count INTEGER,
                summary TEXT,
                last_timestamp INTEGER,
                last_msg_locald_id INTEGER,
                last_msg_type INTEGER,
                last_msg_sub_type INTEGER,
                last_msg_sender TEXT
            );
            CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY);
        """

        if with_reserve:
            create_sqlite_db_with_reserve(db_path, sql_schema)
        else:
            with sqlite3.connect(db_path) as db:
                db.executescript(sql_schema)

        with sqlite3.connect(db_path) as db:
            for s in sessions:
                db.execute(
                    "INSERT INTO SessionTable(username, type, unread_count, summary, "
                    "last_timestamp, last_msg_locald_id, last_msg_type, last_msg_sub_type, last_msg_sender) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        s["username"],
                        s.get("type", 1),
                        s.get("unread_count", 0),
                        s.get("summary", ""),
                        s.get("last_timestamp", self.base_time),
                        s.get("last_msg_id", 1),
                        s.get("last_type", 1),
                        s.get("last_subtype", 0),
                        s.get("last_sender", s["username"]),
                    ),
                )
                db.execute("INSERT OR IGNORE INTO Name2Id(user_name) VALUES(?)", (s["username"],))
            db.commit()

        return db_path

    def build_shards(
        self,
        shard_data: Dict[int, List[Dict[str, Any]]],
        num_shards: int = 5,
        with_reserve: bool = False,
    ) -> List[Path]:
        """
        Create and populate message_0.db through message_{num_shards-1}.db.
        shard_data keys are shard indices (0=current year, 1=last year, etc.).
        """
        shard_paths: List[Path] = []

        for shard_idx in range(num_shards):
            db_path = self.msg_dir / f"message_{shard_idx}.db"
            shard_paths.append(db_path)
            shard_time = self.base_time - (shard_idx * YEAR_SECONDS)
            msgs = shard_data.get(shard_idx, [])

            sql_schema = """
                CREATE TABLE TimeStamp(timestamp INTEGER);
                CREATE TABLE wcdb_builtin_compression_record(
                    tableName TEXT PRIMARY KEY,
                    columns TEXT,
                    rowid INTEGER
                ) WITHOUT ROWID;
                CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER);
            """

            if with_reserve:
                create_sqlite_db_with_reserve(db_path, sql_schema)
            else:
                with sqlite3.connect(db_path) as db:
                    db.executescript(sql_schema)

            with sqlite3.connect(db_path) as db:
                db.execute("INSERT INTO TimeStamp VALUES(?)", (shard_time,))

                # Register users and senders in Name2Id
                chat_tables = set(m["chat"] for m in msgs)
                all_senders = set(m["sender"] for m in msgs).union(chat_tables)
                sender_map: Dict[str, int] = {}
                for rowid, sender in enumerate(sorted(all_senders), start=1):
                    db.execute(
                        "INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(?, ?, 1)",
                        (rowid, sender),
                    )
                    sender_map[sender] = rowid

                # Create Msg_<hash> tables
                for chat in chat_tables:
                    tname = md5_table(chat)
                    db.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS "{tname}"(
                            local_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            server_id INTEGER,
                            local_type INTEGER,
                            sort_seq INTEGER,
                            real_sender_id INTEGER,
                            create_time INTEGER,
                            status INTEGER,
                            upload_status INTEGER,
                            download_status INTEGER,
                            server_seq INTEGER,
                            origin_source INTEGER,
                            source TEXT,
                            message_content TEXT,
                            compress_content TEXT,
                            packed_info_data BLOB,
                            WCDB_CT_message_content INTEGER DEFAULT NULL,
                            WCDB_CT_source INTEGER DEFAULT NULL
                        );
                        """
                    )
                    db.execute(f'CREATE INDEX IF NOT EXISTS "{tname}_SERVERID" ON "{tname}"(server_id);')
                    db.execute(f'CREATE INDEX IF NOT EXISTS "{tname}_SORTSEQ" ON "{tname}"(sort_seq);')

                # Insert messages
                for m in msgs:
                    tname = md5_table(m["chat"])
                    sender_rowid = sender_map.get(m["sender"], 1)
                    kind = m.get("type", TYPE_TEXT)
                    subtype = m.get("subtype", 0)
                    local_type = (subtype << 32) | kind
                    ts = m.get("create_time", shard_time)

                    content: Any = m.get("content", "")
                    compress_col: Any = None
                    wc_ct = WCDB_CT_PLAIN

                    compression = m.get("compression")
                    if compression == "zstd":
                        if isinstance(content, str):
                            content = content.encode("utf-8")
                        content = self._compress_zstd(content)
                        wc_ct = WCDB_CT_ZSTD
                    elif compression == "zlib":
                        if isinstance(content, str):
                            content = content.encode("utf-8")
                        compress_col = zlib.compress(content)
                        content = None
                        wc_ct = WCDB_CT_PLAIN

                    source_val: Any = m.get("source", "")
                    wc_ct_src = WCDB_CT_PLAIN
                    if source_val and m.get("source_compression") == "zstd":
                        if isinstance(source_val, str):
                            source_val = source_val.encode("utf-8")
                        source_val = self._compress_zstd(source_val)
                        wc_ct_src = WCDB_CT_ZSTD

                    db.execute(
                        f"""
                        INSERT INTO "{tname}"(
                            local_id, server_id, local_type, sort_seq, real_sender_id,
                            create_time, status, source, message_content, compress_content,
                            WCDB_CT_message_content, WCDB_CT_source
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            m.get("local_id"),
                            m.get("server_id"),
                            local_type,
                            m.get("sort_seq", ts),
                            sender_rowid,
                            ts,
                            m.get("status", 2),
                            source_val,
                            content,
                            compress_col,
                            wc_ct,
                            wc_ct_src,
                        ),
                    )

                db.commit()

        return shard_paths

    def build_default_dataset(self, with_reserve: bool = False) -> None:
        """
        Build a comprehensive, realistic multi-shard WeChat dataset covering all test cases:
        - Contacts: Alice, Bob, Charlie, Myself, and group chat robot_test@chatroom.
        - Sessions: Alice, Bob, robot_test@chatroom.
        - 5 Shards: message_0.db (2026) to message_4.db (2022).
        - Message kinds: Text, zstd compressed text, legacy zlib text, Image XML,
          AppMsg link (Type 49, subtype 5), Anti-recall notice (Type 10000).
        """
        contacts = [
            {
                "username": "wxid_alice111111",
                "alias": "alice_alias",
                "remark": "Alice Remark",
                "nick_name": "Alice Wonder",
            },
            {
                "username": "wxid_bob2222222",
                "alias": "bob_alias",
                "remark": "Bob Colleague",
                "nick_name": "Bob Builder",
            },
            {
                "username": "wxid_charlie3333",
                "alias": "charlie_c",
                "remark": "Charlie Team",
                "nick_name": "Charlie Chaplin",
            },
            {
                "username": "wxid_me123456789",
                "alias": "my_alias",
                "remark": "Self",
                "nick_name": "Me",
            },
        ]

        chatrooms = [
            {
                "username": "robot_test@chatroom",
                "owner": "wxid_alice111111",
                "members": [
                    "wxid_alice111111",
                    "wxid_bob2222222",
                    "wxid_charlie3333",
                    "wxid_me123456789",
                ],
            }
        ]

        sessions = [
            {
                "username": "wxid_alice111111",
                "summary": "See you tomorrow!",
                "unread_count": 0,
                "last_timestamp": self.base_time,
                "last_sender": "wxid_alice111111",
            },
            {
                "username": "robot_test@chatroom",
                "summary": "Alice: Please check the report",
                "unread_count": 2,
                "last_timestamp": self.base_time - 120,
                "last_sender": "wxid_alice111111",
            },
            {
                "username": "wxid_bob2222222",
                "summary": "Lunch at 12?",
                "unread_count": 0,
                "last_timestamp": self.base_time - 3600,
                "last_sender": "wxid_bob2222222",
            },
        ]

        # Multi-shard messages
        shard_data: Dict[int, List[Dict[str, Any]]] = {
            0: [
                # Shard 0: Current year (2026)
                {
                    "local_id": 1,
                    "server_id": 10001,
                    "chat": "wxid_alice111111",
                    "sender": "wxid_alice111111",
                    "type": TYPE_TEXT,
                    "content": "Hello! How are you doing today?",
                    "create_time": self.base_time - 300,
                },
                {
                    "local_id": 2,
                    "server_id": 10002,
                    "chat": "wxid_alice111111",
                    "sender": "wxid_me123456789",
                    "type": TYPE_TEXT,
                    "compression": "zstd",
                    "content": "I am doing great! Here is a long zstd-compressed reply for testing.",
                    "create_time": self.base_time - 240,
                },
                {
                    "local_id": 3,
                    "server_id": 10003,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_alice111111",
                    "type": TYPE_APPMSG,
                    "subtype": SUBTYPE_LINK,
                    "content": '<msg><appmsg appid="" mediatype="0"><title>Multi-Shard Database Guide</title><url>https://example.com/guide</url><des>In-depth architectural analysis</des><type>5</type></appmsg></msg>',
                    "create_time": self.base_time - 180,
                },
                {
                    "local_id": 4,
                    "server_id": 10004,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_bob2222222",
                    "type": TYPE_IMAGE,
                    "content": '<msg><img hdlength="102400" length="51200" md5="e10adc3949ba59abbe56e057f20f883e" cdnthumburl="https://example.com/thumb.jpg" /></msg>',
                    "create_time": self.base_time - 120,
                },
                {
                    "local_id": 5,
                    "server_id": 10005,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_alice111111",
                    "type": TYPE_TEXT,
                    "content": "Secret message to be recalled shortly",
                    "create_time": self.base_time - 60,
                },
                {
                    "local_id": 6,
                    "server_id": 10006,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_alice111111",
                    "type": TYPE_SYSMSG,
                    "content": "Alice 撤回了一条消息",
                    "create_time": self.base_time - 30,
                },
            ],
            1: [
                # Shard 1: Previous year (2025)
                {
                    "local_id": 101,
                    "server_id": 20001,
                    "chat": "wxid_alice111111",
                    "sender": "wxid_alice111111",
                    "type": TYPE_TEXT,
                    "content": "Annual review message from 2025",
                    "create_time": self.base_time - YEAR_SECONDS - 500,
                },
                {
                    "local_id": 102,
                    "server_id": 20002,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_charlie3333",
                    "type": TYPE_TEXT,
                    "compression": "zlib",
                    "content": "Legacy zlib compressed payload from 2025 project kickoff",
                    "create_time": self.base_time - YEAR_SECONDS - 400,
                },
            ],
            2: [
                # Shard 2: 2024
                {
                    "local_id": 201,
                    "server_id": 30001,
                    "chat": "robot_test@chatroom",
                    "sender": "wxid_bob2222222",
                    "type": TYPE_TEXT,
                    "content": "Historical message from 2024 database shard",
                    "create_time": self.base_time - 2 * YEAR_SECONDS,
                }
            ],
            3: [
                # Shard 3: 2023
                {
                    "local_id": 301,
                    "server_id": 40001,
                    "chat": "wxid_alice111111",
                    "sender": "wxid_alice111111",
                    "type": TYPE_TEXT,
                    "content": "Ancient archive text from 2023",
                    "create_time": self.base_time - 3 * YEAR_SECONDS,
                }
            ],
            4: [
                # Shard 4: 2022
                {
                    "local_id": 401,
                    "server_id": 50001,
                    "chat": "wxid_bob2222222",
                    "sender": "wxid_bob2222222",
                    "type": TYPE_TEXT,
                    "content": "Initial onboarding message in 2022",
                    "create_time": self.base_time - 4 * YEAR_SECONDS,
                }
            ],
        }

        self.build_contact_db(contacts, chatrooms, with_reserve=with_reserve)
        self.build_session_db(sessions, with_reserve=with_reserve)
        self.build_shards(shard_data, num_shards=5, with_reserve=with_reserve)

    def encrypt_all(self, enc_key: Union[bytes, str], target_dir: Union[str, Path]) -> Path:
        """
        Encrypt all SQLite databases in this fixture into a target directory
        using the SQLCipher 4 generator.
        """
        target_dir = Path(target_dir)
        for sub in ("message", "contact", "session"):
            src_sub = self.root / sub
            dst_sub = target_dir / sub
            dst_sub.mkdir(parents=True, exist_ok=True)
            for db_file in src_sub.glob("*.db"):
                dst_file = dst_sub / db_file.name
                encrypt_sqlite_db(db_file, dst_file, enc_key)

        return target_dir
