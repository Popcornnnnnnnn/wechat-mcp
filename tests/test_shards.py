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

"""Unit tests for multi-shard DB engine, connection pooling, Name2Id mapping, and decompression."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import zlib

import pytest

try:
    import zstandard
except ImportError:
    zstandard = None

from wechat_mcp.db.decompress import (
    MAX_CONTENT_BYTES,
    WCDB_CT_PLAIN,
    WCDB_CT_ZSTD,
    decompress_content,
)
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.sender import SenderResolver
from wechat_mcp.db.shards import ShardManager, md5_table


@pytest.fixture
def multi_shard_environment(tmp_path: Path) -> Path:
    """Create synthetic multi-shard directory structure with 3 shards."""
    db_storage = tmp_path / "db_storage"
    msg_dir = db_storage / "message"
    contact_dir = db_storage / "contact"
    session_dir = db_storage / "session"
    msg_dir.mkdir(parents=True)
    contact_dir.mkdir(parents=True)
    session_dir.mkdir(parents=True)

    # 1. Contact database
    with sqlite3.connect(contact_dir / "contact.db") as db:
        db.execute("""
            CREATE TABLE contact(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                alias TEXT,
                remark TEXT,
                nick_name TEXT
            );
        """)
        db.execute("INSERT INTO contact VALUES(1, 'wxid_alice111', 'alice_alias', 'Alice Remark', 'Alice Nick');")
        db.execute("INSERT INTO contact VALUES(2, 'wxid_bob222', 'bob_alias', '', 'Bob Nick');")
        db.execute("INSERT INTO contact VALUES(3, 'wxid_charlie333', '', '', '');")
        db.commit()

    # 2. Session database
    with sqlite3.connect(session_dir / "session.db") as db:
        db.execute("""
            CREATE TABLE SessionTable(
                username TEXT PRIMARY KEY,
                type INTEGER,
                unread_count INTEGER,
                summary TEXT,
                last_timestamp INTEGER,
                last_msg_sender TEXT
            );
        """)
        db.execute("INSERT INTO SessionTable VALUES('chat_target@chatroom', 1, 0, 'last msg', 1710000000, 'wxid_alice111');")
        db.execute("INSERT INTO SessionTable VALUES('wxid_alice111', 1, 0, 'hello alice', 1709000000, 'wxid_alice111');")
        db.commit()

    # 3. Message shards (message_0.db, message_1.db, message_2.db)
    tname = md5_table("chat_target@chatroom")

    # Shard 0: 2026 messages
    with sqlite3.connect(msg_dir / "message_0.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INTEGER);")
        db.execute("INSERT INTO TimeStamp VALUES(1710000000);")
        db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER);")
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(1, 'wxid_alice111', 0);")
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(2, 'wxid_bob222', 0);")

        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER,
                local_type INTEGER,
                sort_seq INTEGER,
                real_sender_id INTEGER,
                create_time INTEGER,
                status INTEGER,
                source TEXT,
                message_content TEXT,
                compress_content BLOB,
                WCDB_CT_message_content INTEGER,
                WCDB_CT_source INTEGER
            );
        """)
        db.execute(
            f'INSERT INTO "{tname}" VALUES(1, 1001, 1, 10, 1, 1710000100, 2, "", "Shard 0 Msg 1 from Alice", NULL, 0, 0);'
        )
        db.execute(
            f'INSERT INTO "{tname}" VALUES(2, 1002, 1, 20, 2, 1710000200, 2, "", "Shard 0 Msg 2 from Bob", NULL, 0, 0);'
        )
        db.commit()

    # Shard 1: 2025 messages - Note: rowid 1 in Shard 1 is Bob, not Alice!
    with sqlite3.connect(msg_dir / "message_1.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INTEGER);")
        db.execute("INSERT INTO TimeStamp VALUES(1680000000);")
        db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER);")
        # In shard 1: rowid 1 maps to wxid_bob222!
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(1, 'wxid_bob222', 0);")
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(2, 'wxid_charlie333', 0);")

        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER,
                local_type INTEGER,
                sort_seq INTEGER,
                real_sender_id INTEGER,
                create_time INTEGER,
                status INTEGER,
                source TEXT,
                message_content TEXT,
                compress_content BLOB,
                WCDB_CT_message_content INTEGER,
                WCDB_CT_source INTEGER
            );
        """)
        # real_sender_id=1 in Shard 1 must resolve to wxid_bob222
        db.execute(
            f'INSERT INTO "{tname}" VALUES(1, 901, 1, 5, 1, 1680000100, 2, "", "Shard 1 Msg 1 from Bob", NULL, 0, 0);'
        )
        db.commit()

    return db_storage


def test_shard_manager_discovery_and_attach(multi_shard_environment: Path):
    """Test ShardManager discovers shards and executes ATTACH."""
    msg_dir = multi_shard_environment / "message"
    mgr = ShardManager(msg_dir)
    shards = mgr.discover_shards()
    assert len(shards) == 2
    assert shards[0].name == "message_0.db"
    assert shards[1].name == "message_1.db"

    conn = mgr.get_connection()
    databases = [row["name"] for row in conn.execute("PRAGMA database_list;").fetchall()]
    assert "main" in databases
    assert "shard_1" in databases

    # Verify TEMP VIEW union creation
    tname = md5_table("chat_target@chatroom")
    assert mgr.table_exists(tname)
    rows = conn.execute(f'SELECT local_id, server_id, _shard FROM "v_{tname}" ORDER BY server_id;').fetchall()
    assert len(rows) == 3

    # Check that rows come from both main and shard_1
    found_shards = set(r["_shard"] for r in rows)
    assert "main" in found_shards
    assert "shard_1" in found_shards
    mgr.close()


def test_connection_pooling_and_reuse_50_queries(multi_shard_environment: Path):
    """Test connection pool reuses connection across 50+ queries without descriptor leaks."""
    reader = HistoryReader(multi_shard_environment)
    initial_conn = reader.shards.get_connection()

    for idx in range(60):
        stats = reader.get_stats()
        assert stats["chats"] >= 1
        assert stats["messages"] == 3
        current_conn = reader.shards.get_connection()
        # Ensure exact same connection object is reused
        assert current_conn is initial_conn

    reader.shards.close()


def test_per_shard_name2id_rowid_mapping(multi_shard_environment: Path):
    """Test sender resolution respects per-shard Name2Id rowids."""
    reader = HistoryReader(multi_shard_environment)
    data = reader.get_messages("chat_target@chatroom", limit=100)
    messages = data["messages"]
    assert len(messages) == 3

    # Find message with server_id=1001 (from Shard 0, real_sender_id=1)
    msg_1001 = next(m for m in messages if m["server_id"] == 1001)
    assert msg_1001["sender_wxid"] == "wxid_alice111"
    # Display name hierarchy: remark > nick_name > alias > username
    assert msg_1001["sender"] == "Alice Remark"

    # Find message with server_id=901 (from Shard 1, real_sender_id=1)
    # real_sender_id=1 in Shard 1 MUST resolve to Bob, not Alice!
    msg_901 = next(m for m in messages if m["server_id"] == 901)
    assert msg_901["sender_wxid"] == "wxid_bob222"
    assert msg_901["sender"] == "Bob Nick"

    reader.shards.close()


def test_wcdb_zstd_and_zlib_decompression():
    """Test decompression of zstd, zlib, raw deflate, plain text, and bomb protection."""
    # 1. Plain text
    assert decompress_content("plain text message") == "plain text message"

    # 2. None / empty
    assert decompress_content(None) == ""
    assert decompress_content(b"") == ""

    # 3. Zlib in message_content
    raw_str = "Hello via zlib compression!"
    zlib_blob = zlib.compress(raw_str.encode("utf-8"))
    assert decompress_content(zlib_blob) == raw_str

    # 4. Zlib in compress_content column
    assert decompress_content(None, wc_ct=0, compress_col=zlib_blob) == raw_str

    # 5. Raw deflate (-15) fallback in compress_content
    raw_deflate_blob = zlib.compress(raw_str.encode("utf-8"))[2:-4]  # Strip zlib header & checksum
    assert decompress_content(None, wc_ct=0, compress_col=raw_deflate_blob) == raw_str

    # 6. Zstandard compression
    if zstandard:
        cctx = zstandard.ZstdCompressor(level=3)
        zstd_blob = cctx.compress(raw_str.encode("utf-8"))
        assert decompress_content(zstd_blob, wc_ct=WCDB_CT_ZSTD) == raw_str

    # 7. Corrupted zstd/zlib payload
    corrupted_zstd = b"\x28\xb5\x2f\xfd\x00\x11\x22\x33\x44"
    assert decompress_content(corrupted_zstd, wc_ct=4) == "[Decompression Failed]"

    corrupted_zlib = b"\x78\x9c\xff\xff\x00\x00"
    assert decompress_content(corrupted_zlib) == "[Decompression Failed]"

    # 8. Bounded size truncation for oversized string
    huge_str = "A" * (MAX_CONTENT_BYTES + 500)
    res = decompress_content(huge_str)
    assert "[TRUNCATED]" in res
    assert len(res) <= MAX_CONTENT_BYTES + 50


def test_history_reader_corner_cases(multi_shard_environment: Path, tmp_path: Path):
    """Test boundary conditions: missing chat, missing Name2Id, extreme limits, escaping."""
    reader = HistoryReader(multi_shard_environment)

    # 1. Nonexistent chat returns empty structure cleanly
    res_none = reader.get_messages("nonexistent_contact@chatroom", limit=10)
    assert res_none["count"] == 0
    assert res_none["messages"] == []
    assert res_none["total"] == 0

    # 2. Extreme limits / offsets clamped safely
    res_clamped = reader.get_messages("chat_target@chatroom", limit=-50, offset=-20)
    assert res_clamped["limit"] == 1
    assert res_clamped["offset"] == 0

    # 3. Contact search escaping % and _
    contacts = reader.list_contacts(query="Alice%")
    assert len(contacts) == 0  # No contact has literal 'Alice%'
    contacts_valid = reader.list_contacts(query="Alice")
    assert len(contacts_valid) >= 1

    # 4. Missing Name2Id fallback in fresh shard
    orphan_db = tmp_path / "orphan"
    orphan_msg = orphan_db / "message"
    orphan_msg.mkdir(parents=True)
    tname = md5_table("orphan_user")
    with sqlite3.connect(orphan_msg / "message_0.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        # No Name2Id table!
        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INT, server_id INT, local_type INT, sort_seq INT,
                real_sender_id INT, create_time INT, status INT, source TEXT,
                message_content TEXT, compress_content TEXT,
                WCDB_CT_message_content INT, WCDB_CT_source INT
            );
        """)
        db.execute(f'INSERT INTO "{tname}" VALUES(1, 555, 1, 1, 777, 1700000000, 2, "", "test", NULL, 0, 0);')

    orphan_reader = HistoryReader(orphan_db)
    res_orphan = orphan_reader.get_messages("orphan_user", limit=10)
    assert res_orphan["count"] == 1
    assert res_orphan["messages"][0]["sender"] == "777"
    assert res_orphan["messages"][0]["sender_wxid"] == "777"

    reader.shards.close()
    orphan_reader.shards.close()


def test_concurrent_multithread_queries_no_collision(multi_shard_environment: Path):
    """Test 10+ concurrent threads executing get_messages() and get_stats() with zero collision."""
    import concurrent.futures

    reader = HistoryReader(multi_shard_environment)
    errors = []
    results = []

    def worker_messages(worker_id: int):
        for _ in range(15):
            res = reader.get_messages("chat_target@chatroom", limit=10)
            if res["count"] != 3:
                raise ValueError(f"Worker {worker_id}: expected 3 messages, got {res['count']}")
            for msg in res["messages"]:
                if not msg["shard"] or not isinstance(msg["shard"], str):
                    raise ValueError(f"Worker {worker_id}: corrupted shard tag {msg['shard']}")
                if not msg["sender_wxid"]:
                    raise ValueError(f"Worker {worker_id}: missing sender_wxid")
            results.append(res["count"])

    def worker_stats(worker_id: int):
        for _ in range(15):
            st = reader.get_stats()
            if st["messages"] != 3:
                raise ValueError(f"Worker {worker_id}: expected 3 messages in stats, got {st['messages']}")
            results.append(st["messages"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = []
        for i in range(6):
            futures.append(executor.submit(worker_messages, i))
            futures.append(executor.submit(worker_stats, i + 10))

        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:
                errors.append(e)

    reader.shards.close()
    assert len(errors) == 0, f"Encountered thread concurrency errors: {errors}"
    assert len(results) == 12 * 15


def test_cold_start_empty_storage_returns_zeroes(tmp_path: Path):
    """Test cold-start handling on completely empty storage directory."""
    empty_dir = tmp_path / "empty_storage"
    empty_dir.mkdir(parents=True)

    reader = HistoryReader(empty_dir)

    # ShardManager on empty dir
    assert reader.shards.discover_shards() == []
    assert reader.shards.list_chat_tables() == []
    assert reader.shards.table_exists("any_table") is False

    # Stats returns clean zeroed dict
    stats = reader.get_stats()
    assert stats["chats"] == 0
    assert stats["messages"] == 0
    assert stats["contacts"] == 0
    assert stats["shard_count"] == 0
    assert stats["from"] == 0
    assert stats["to"] > 0

    # Queries return empty lists without raising
    assert reader.list_chats() == []
    assert reader.list_contacts() == []
    assert reader.search_messages("test") == []

    reader.shards.close()


def test_connection_closing_and_no_fd_leakage(multi_shard_environment: Path):
    """Test contextlib.closing prevents file descriptor leaks over 50 queries."""
    reader = HistoryReader(multi_shard_environment)

    # Warm up connections
    reader.get_stats()
    reader.list_contacts()
    reader.list_chats()

    baseline_fds = len(os.listdir("/dev/fd"))

    # Execute 50 consecutive queries opening contact.db and session.db
    for _ in range(50):
        _ = reader.get_stats()
        _ = reader.list_contacts()
        _ = reader.list_chats()

    current_fds = len(os.listdir("/dev/fd"))
    reader.shards.close()

    # FD growth must be zero (or strictly bounded, delta <= 1)
    assert abs(current_fds - baseline_fds) <= 1, (
        f"File descriptors leaked: baseline={baseline_fds}, current={current_fds}"
    )
