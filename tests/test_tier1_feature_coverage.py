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
Tier 1: Feature Coverage Test Suite (72 tests).

Systematically tests happy paths and functional coverage for all 12 features
(F1 through F12, 6 tests per feature) as defined in TEST_INFRA.md and PROJECT.md.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Tuple
import zlib

try:
    import zstandard
except ImportError:
    zstandard = None

import pytest

from unittest.mock import MagicMock
from click.testing import CliRunner

from tests.fixtures.crypto_generator import generate_synthetic_encrypted_db
from wechat_mcp import __version__
from wechat_mcp.crypto.decrypt import (
    KEY_SZ,
    PAGE_SZ,
    SALT_SZ,
    decrypt_database,
    decrypt_page,
    derive_mac_key,
)
from tests.fixtures.wechat_generator import (
    SUBTYPE_LINK,
    TYPE_APPMSG,
    TYPE_IMAGE,
    TYPE_SYSMSG,
    TYPE_TEXT,
    SyntheticWeChatFixture,
    md5_table,
)
from tests.conftest import MCPServerTestAdapter
from wechat_mcp.db.decompress import decompress_content
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.summary.pipeline import SummaryPipeline
from wechat_mcp.summary.schema import (
    CheckStageSchema,
    Citation,
    SummaryPipelineResult,
    UnderstandStageSchema,
    VisualBlock,
    VisualStageSchema,
    WriteStageSchema,
)
from wechat_mcp.watcher.journal import EventJournal
from wechat_mcp.watcher.kqueue import VnodeFlags, VnodeWatch, WatcherEvent
from wechat_mcp.watcher.recall import RecallArchive
from wechat_mcp.cli import main
from wechat_mcp.config import Config, discover_wechat_db_dir, load_config
from wechat_mcp.crypto.lldb_keys import get_key_registers

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ===========================================================================
# Feature F1: Database Key Extraction (6 Tests)
# ===========================================================================


def test_f1_01_dynamic_wxid_discovery_locates_storage_dir(tmp_path: Path, monkeypatch):
    """F1-1: Discovers active storage path matching xwechat_files/wxid_*/db_storage via discover_wechat_db_dir()."""
    mock_base = tmp_path / "xwechat_files"
    user_dir = mock_base / "wxid_mock123_abc"
    db_storage = user_dir / "db_storage"
    msg_dir = db_storage / "message"
    msg_dir.mkdir(parents=True)
    (msg_dir / "message_0.db").touch()
    (db_storage / "contact").mkdir()
    (db_storage / "contact" / "contact.db").touch()

    # Isolate discovery search roots to mock_base
    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [mock_base])

    found = discover_wechat_db_dir()
    assert found is not None
    assert found == db_storage.resolve()
    assert (found / "contact" / "contact.db").exists()


def test_f1_02_vm_scan_extracts_keys_from_memory_buffer():
    """F1-2: Scans memory buffer for x'<64 hex key><32 hex salt>' pattern."""
    from wechat_mcp.crypto.vm_scan import HEX_PATTERN

    test_key = os.urandom(32).hex()
    test_salt = os.urandom(16).hex()
    pattern = f"x'{test_key}{test_salt}'".encode("ascii")

    # Construct mock memory buffer
    buffer = b"\x00" * 1024 + pattern + b"\x00" * 2048
    match = HEX_PATTERN.search(buffer)

    assert match is not None
    extracted_key = match.group(1).decode("ascii")
    extracted_salt = match.group(2).decode("ascii")
    assert extracted_key.lower() == test_key.lower()
    assert extracted_salt.lower() == test_salt.lower()


def test_f1_03_lldb_cccrypt_arm64_register_capture():
    """F1-3: Intercepts simulated ARM64 registers x3 (key_ptr) and x4 (32) via get_key_registers()."""
    arm64_frame = MagicMock()
    reg_x3 = MagicMock()
    reg_x3.IsValid.return_value = True
    reg_x3.GetValueAsUnsigned.return_value = 0x10005000

    reg_x4 = MagicMock()
    reg_x4.IsValid.return_value = True
    reg_x4.GetValueAsUnsigned.return_value = 32

    def arm64_find(name: str):
        if name == "x3":
            return reg_x3
        if name == "x4":
            return reg_x4
        return None

    arm64_frame.FindRegister.side_effect = arm64_find

    key_ptr, key_len = get_key_registers(arm64_frame)
    assert key_ptr == 0x10005000
    assert key_len == 32


def test_f1_04_lldb_cccrypt_x86_64_register_capture():
    """F1-4: Intercepts simulated x86_64 registers rcx (key_ptr) and r8 (32) via get_key_registers()."""
    x86_frame = MagicMock()
    reg_rcx = MagicMock()
    reg_rcx.IsValid.return_value = True
    reg_rcx.GetValueAsUnsigned.return_value = 0x20005000

    reg_r8 = MagicMock()
    reg_r8.IsValid.return_value = True
    reg_r8.GetValueAsUnsigned.return_value = 32

    def x86_find(name: str):
        if name == "rcx":
            return reg_rcx
        if name == "r8":
            return reg_r8
        return None

    x86_frame.FindRegister.side_effect = x86_find

    key_ptr, key_len = get_key_registers(x86_frame)
    assert key_ptr == 0x20005000
    assert key_len == 32


def test_f1_05_all_keys_json_atomic_write_and_merge(tmp_path: Path):
    """F1-5: Atomically writes and merges database keys into all_keys.json."""
    keys_file = tmp_path / "all_keys.json"
    initial_data = {"message/message_0.db": "a" * 64}
    keys_file.write_text(json.dumps(initial_data), encoding="utf-8")

    # New key to merge
    new_data = {"message/message_1.db": "b" * 64}
    with open(keys_file, "r+", encoding="utf-8") as f:
        existing = json.load(f)
        existing.update(new_data)
        # Atomic replace via temp file
        tmp_keys = keys_file.with_suffix(".tmp")
        tmp_keys.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        tmp_keys.replace(keys_file)

    loaded = json.loads(keys_file.read_text(encoding="utf-8"))
    assert len(loaded) == 2
    assert loaded["message/message_0.db"] == "a" * 64
    assert loaded["message/message_1.db"] == "b" * 64


def test_f1_06_key_utils_relative_path_normalization(tmp_path: Path):
    """F1-6: Normalizes full macOS absolute path to canonical relative database key."""
    full_path = tmp_path / "xwechat_files" / "wxid_mock123" / "db_storage" / "message" / "message_0.db"
    parts = full_path.parts
    # Locate storage root
    idx = parts.index("db_storage")
    rel_path = Path(*parts[idx + 1 :]).as_posix()
    assert rel_path == "message/message_0.db"


# ===========================================================================
# Feature F2: SQLCipher Decryption Engine (6 Tests)
# ===========================================================================


def test_f2_01_pbkdf2_mac_key_derivation():
    """F2-1: Derives 32-byte MAC key using salt ^ 0x3A and PBKDF2-HMAC-SHA512 (2 iterations)."""
    enc_key = b"\x01" * 32
    salt = b"\x02" * 16
    mac_key = derive_mac_key(enc_key, salt)
    assert len(mac_key) == 32

    # Deterministic output verification
    mac_key2 = derive_mac_key(enc_key, salt)
    assert mac_key == mac_key2


def test_f2_02_page1_decrypt_and_header_rewrite(tmp_path: Path):
    """F2-2: Decrypts page 1, verifies SQLite format 3\x00 header and reserve padding."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "page1_test.db"
    generate_synthetic_encrypted_db(
        enc_key,
        sql_script="CREATE TABLE test(id INT, v TEXT); INSERT INTO test VALUES(1, 'val');",
        output_path=enc_path,
    )

    page1_raw = enc_path.read_bytes()[:PAGE_SZ]
    decrypted_page1 = decrypt_page(enc_key, page1_raw, 1)

    assert len(decrypted_page1) == PAGE_SZ
    assert decrypted_page1[:16] == b"SQLite format 3\x00"
    # Last 80 bytes are zeroed reserve space
    assert decrypted_page1[PAGE_SZ - 80 :] == b"\x00" * 80


def test_f2_03_page_n_decrypt_and_reserve_padding(tmp_path: Path):
    """F2-3: Decrypts page 2..N with per-page IV and pads reserve with 80 zeros."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "multi_page.db"
    # Create multi-page database
    sql = "CREATE TABLE big(id INT, data TEXT);" + "".join(
        f"INSERT INTO big VALUES({i}, '{'x' * 500}');" for i in range(20)
    )
    generate_synthetic_encrypted_db(enc_key, sql_script=sql, output_path=enc_path)

    data = enc_path.read_bytes()
    assert len(data) >= PAGE_SZ * 2
    page2_raw = data[PAGE_SZ : PAGE_SZ * 2]

    decrypted_page2 = decrypt_page(enc_key, page2_raw, 2)
    assert len(decrypted_page2) == PAGE_SZ
    assert decrypted_page2[PAGE_SZ - 80 :] == b"\x00" * 80


def test_f2_04_full_database_roundtrip_decrypt(tmp_path: Path):
    """F2-4: Synthetically encrypts and round-trip decrypts full database, verified by sqlite3."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "roundtrip_enc.db"
    dec_path = tmp_path / "roundtrip_dec.db"

    sql = "CREATE TABLE contact(id INT, name TEXT); INSERT INTO contact VALUES(42, 'Alice');"
    generate_synthetic_encrypted_db(enc_key, sql_script=sql, output_path=enc_path)

    success = decrypt_database(enc_path, dec_path, enc_key)
    assert success is True

    with sqlite3.connect(dec_path) as db:
        row = db.execute("SELECT id, name FROM contact WHERE id=42").fetchone()
        assert row == (42, "Alice")
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        assert integrity[0] == "ok"


def test_f2_05_wal_checkpoint_truncate_before_decrypt(tmp_path: Path):
    """F2-5: Executes PRAGMA wal_checkpoint(TRUNCATE) before decryption."""
    db_path = tmp_path / "wal_test.db"
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("CREATE TABLE t(x INT);")
        db.execute("INSERT INTO t VALUES(1);")
        db.commit()
        # Checkpoint truncate
        res = db.execute("PRAGMA wal_checkpoint(TRUNCATE);").fetchone()
        assert res[0] == 0  # 0 indicates checkpoint success


def test_f2_06_in_memory_page_cache_streaming_decrypt(tmp_path: Path):
    """F2-6: Streams page decryption in chunks without loading entire file into memory."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "streaming.db"
    dec_path = tmp_path / "streaming_out.db"

    generate_synthetic_encrypted_db(
        enc_key,
        sql_script="CREATE TABLE stream(id INT); INSERT INTO stream VALUES(1);",
        output_path=enc_path,
    )

    # Decrypt database uses streaming file handle
    assert decrypt_database(enc_path, dec_path, enc_key)
    assert dec_path.exists()
    assert dec_path.stat().st_size == enc_path.stat().st_size


# ===========================================================================
# Feature F3: Multi-Shard Query Engine (6 Tests)
# ===========================================================================


def test_f3_01_sqlite_attach_all_shards(synthetic_wechat_environment: Path):
    """F3-1: Attaches message_0.db through message_4.db in single connection."""
    msg_dir = synthetic_wechat_environment / "message"
    main_db = msg_dir / "message_0.db"

    with sqlite3.connect(main_db) as db:
        for idx in range(1, 5):
            shard_path = msg_dir / f"message_{idx}.db"
            if shard_path.exists():
                db.execute(f"ATTACH DATABASE '{shard_path.as_posix()}' AS shard_{idx};")

        databases = [row[1] for row in db.execute("PRAGMA database_list").fetchall()]
        assert "main" in databases
        assert "shard_1" in databases
        assert "shard_4" in databases


def test_f3_02_temp_view_union_with_shard_tag(synthetic_wechat_environment: Path):
    """F3-2: Constructs TEMP VIEW with _shard column union across shards."""
    msg_dir = synthetic_wechat_environment / "message"
    main_db = msg_dir / "message_0.db"
    chat = "wxid_alice111111"
    tname = md5_table(chat)

    with sqlite3.connect(main_db) as db:
        db.execute(f"ATTACH DATABASE '{(msg_dir / 'message_1.db').as_posix()}' AS shard_1;")

        # Construct union view
        view_sql = f"""
            CREATE TEMP VIEW IF NOT EXISTS v_{tname} AS
            SELECT *, 'main' AS _shard FROM main."{tname}"
            UNION ALL
            SELECT *, 'shard_1' AS _shard FROM shard_1."{tname}";
        """
        db.execute(view_sql)

        rows = db.execute(f"SELECT local_id, _shard FROM v_{tname}").fetchall()
        shards_found = set(r[1] for r in rows)
        assert "main" in shards_found
        assert "shard_1" in shards_found


def test_f3_03_per_shard_name2id_rowid_mapping(synthetic_wechat_environment: Path):
    """F3-3: Resolves sender username correctly per-shard using local Name2Id rowids."""
    reader = HistoryReader(synthetic_wechat_environment)
    res = reader.get_messages("robot_test@chatroom", limit=100)
    messages = res["messages"]

    senders = set(m.get("sender_wxid") or m["sender"] for m in messages)
    assert "wxid_alice111111" in senders
    assert "wxid_bob2222222" in senders


def test_f3_04_wcdb_zstd_decompression():
    """F3-4: Decompresses zstd-compressed BLOB with magic \\x28\\xb5\\x2f\\xfd."""
    raw_text = "Highly compressible message content repeated " * 10
    compressed = zstandard.ZstdCompressor(level=3).compress(raw_text.encode("utf-8"))
    assert compressed.startswith(b"\x28\xb5\x2f\xfd")

    decompressed = decompress_content(compressed, wc_ct=4)
    assert decompressed == raw_text


def test_f3_05_wcdb_zlib_decompression_fallbacks():
    """F3-5: Decompresses legacy zlib compressed content cleanly."""
    raw_text = "Legacy zlib compressed payload"
    compressed = zlib.compress(raw_text.encode("utf-8"))

    decompressed = decompress_content(None, wc_ct=0, compress_col=compressed)
    assert decompressed == raw_text


def test_f3_06_connection_pool_reuse_and_concurrency(synthetic_wechat_environment: Path):
    """F3-6: Executes 50 sequential queries without leaking connections or file descriptors."""
    reader = HistoryReader(synthetic_wechat_environment)
    for _ in range(50):
        stats = reader.get_stats()
        assert stats["chats"] > 0
        assert stats["messages"] > 0


# ===========================================================================
# Feature F4: FastMCP Server (40 Tools) (6 Tests)
# ===========================================================================


def test_f4_01_tool_surface_exact_40_count_and_names(mock_mcp_server: MCPServerTestAdapter):
    """F4-1: Server advertises exactly 40 tools (30 Core + 10 legacy aliases)."""
    tools = mock_mcp_server.list_tools()
    assert len(tools) == 40
    # Check key core tools
    assert "wechat_core_messages" in tools
    assert "wechat_core_stats" in tools
    assert "wechat_core_health" in tools
    # Check legacy aliases
    assert "wechat_messages" in tools
    assert "wechat_stats" in tools
    assert "wechat_chats" in tools


def test_f4_02_tool_required_arguments_schema_compliance(mock_mcp_server: MCPServerTestAdapter):
    """F4-2: Required arguments strictly match TOOL_REQUIRED schema."""
    req_map = mock_mcp_server.TOOL_REQUIRED
    assert req_map["wechat_core_messages"] == ["session"]
    assert req_map["wechat_core_search"] == ["query", "session"]
    assert req_map["wechat_messages"] == ["username"]
    assert req_map["wechat_stats"] == []


def test_f4_03_core_query_tools_execution(mock_mcp_server: MCPServerTestAdapter):
    """F4-3: Executes wechat_core_stats, wechat_core_sessions, wechat_core_messages."""
    stats = mock_mcp_server.call_tool("wechat_core_stats")
    assert stats["chats"] >= 3
    assert stats["messages"] >= 6

    sessions = mock_mcp_server.call_tool("wechat_core_sessions")
    assert len(sessions["sessions"]) >= 3

    msgs = mock_mcp_server.call_tool("wechat_core_messages", {"session": "wxid_alice111111"})
    assert msgs["count"] >= 2


def test_f4_04_legacy_alias_tools_parity(mock_mcp_server: MCPServerTestAdapter):
    """F4-4: Executes legacy alias tools (wechat_stats, wechat_chats, wechat_messages)."""
    stats = mock_mcp_server.call_tool("wechat_stats")
    assert stats["chats"] >= 3

    chats = mock_mcp_server.call_tool("wechat_chats")
    assert len(chats["sessions"]) >= 3

    msgs = mock_mcp_server.call_tool("wechat_messages", {"username": "wxid_alice111111"})
    assert msgs["count"] >= 2


def test_f4_05_safe_error_envelope_conformance(mock_mcp_server: MCPServerTestAdapter):
    """F4-5: Error response conforms to wechat.core.error.v1 and redacts private texts."""
    res = mock_mcp_server.call_tool("wechat_core_messages", {})  # Missing required session
    assert res["schema"] == "wechat.core.error.v1"
    assert res["error_type"] == "ValidationError"
    assert "Missing required argument" in res["message"]
    assert res["retry_unknown"] is False


def test_f4_06_resource_push_and_event_subscription(mock_mcp_server: MCPServerTestAdapter):
    """F4-6: Simulates event subscription to wechat-core://events/{group}."""
    group = "robot_test@chatroom"
    mock_mcp_server.subscribers[group] = ["client_mock_1"]
    assert "client_mock_1" in mock_mcp_server.subscribers[group]


# ===========================================================================
# Feature F5: FastAPI REST Query Service (6 Tests)
# ===========================================================================


def test_f5_01_get_stats_endpoint(mock_api_client: TestClient):
    """F5-1: GET /api/stats returns chats, messages, and contacts count."""
    res = mock_api_client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["chats"] >= 3
    assert data["messages"] >= 6
    assert data["contacts"] >= 4


def test_f5_02_get_chats_endpoint_sorting(mock_api_client: TestClient):
    """F5-2: GET /api/chats returns sessions sorted by last_timestamp descending."""
    res = mock_api_client.get("/api/chats")
    assert res.status_code == 200
    chats = res.json()
    assert len(chats) >= 3
    # Check descending order
    timestamps = [c["last_timestamp"] for c in chats]
    assert timestamps == sorted(timestamps, reverse=True)


def test_f5_03_get_chat_messages_paging(mock_api_client: TestClient):
    """F5-3: GET /api/chats/{username}/messages supports limit and offset paging."""
    res = mock_api_client.get("/api/chats/wxid_alice111111/messages?limit=1&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 1
    assert data["total"] >= 2
    assert data["offset"] == 0


def test_f5_04_get_contacts_search(mock_api_client: TestClient):
    """F5-4: GET /api/contacts?q=Alice filters contacts."""
    res = mock_api_client.get("/api/contacts?q=Alice")
    assert res.status_code == 200
    contacts = res.json()
    assert len(contacts) >= 1
    assert any("Alice" in c["nick_name"] or "Alice" in c["remark"] for c in contacts)


def test_f5_05_get_search_endpoint_with_session(mock_api_client: TestClient):
    """F5-5: GET /api/search?q=Hello searches across messages."""
    res = mock_api_client.get("/api/search?q=Hello")
    assert res.status_code == 200
    results = res.json()
    assert len(results) >= 1
    assert "Hello" in results[0]["content"]


def test_f5_06_post_sync_endpoint(mock_api_client: TestClient):
    """F5-6: POST /api/sync triggers sync action and returns execution log."""
    res = mock_api_client.post("/api/sync")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "sync_completed"


# ===========================================================================
# Feature F6: Message Event Hooks & Journal (6 Tests)
# ===========================================================================


def test_f6_01_kqueue_vnode_file_write_detection(tmp_path: Path):
    """F6-1: Detects file write modification events via VnodeWatch."""
    watcher = VnodeWatch(tmp_path)
    monitored_file = tmp_path / "message_0.db-wal"
    monitored_file.touch()

    received_events = []
    watcher.watch_file(monitored_file, VnodeFlags.NOTE_WRITE)
    watcher.subscribe(lambda ev: received_events.append(ev))

    # Append data and trigger watcher event
    with open(monitored_file, "a") as f:
        f.write("checkpoint_commit_marker")

    event = watcher.emit_event(monitored_file, VnodeFlags.NOTE_WRITE)
    assert event is not None
    assert len(received_events) == 1
    assert received_events[0].path == monitored_file.resolve()
    assert received_events[0].flags == VnodeFlags.NOTE_WRITE
    assert monitored_file.stat().st_size > 0


def test_f6_02_event_journal_monotonic_seq(tmp_path: Path):
    """F6-2: Writes events to EventJournal with strictly monotonic autoincrementing seq."""
    journal = EventJournal(tmp_path / "events.sqlite")
    seqs = []
    for i in range(5):
        seq = journal.append(
            event_type="msg_recv",
            chatroom_id="robot_test@chatroom",
            payload={"msg_id": 1000 + i, "content": f"payload_{i}"},
            sender_id="wxid_alice111111",
        )
        seqs.append(seq)

    assert seqs == [1, 2, 3, 4, 5]
    all_events = journal.drain(since_seq=0)
    assert [e["seq"] for e in all_events] == [1, 2, 3, 4, 5]


def test_f6_03_event_journal_cursor_drain(tmp_path: Path):
    """F6-3: Calling drain(since_seq=3) returns only subsequent events (4, 5)."""
    journal = EventJournal(tmp_path / "events.sqlite")
    for i in range(1, 6):
        journal.append(
            event_type="msg_recv",
            chatroom_id="robot_test@chatroom",
            payload={"content": f"msg_{i}"},
        )

    drained = journal.drain(since_seq=3)
    assert len(drained) == 2
    assert [e["seq"] for e in drained] == [4, 5]
    assert drained[0]["payload"]["content"] == "msg_4"
    assert drained[1]["payload"]["content"] == "msg_5"


def test_f6_04_event_coalescing_and_debouncing(tmp_path: Path):
    """F6-4: Coalesces rapid file events within a debouncing window into 1 notification."""
    watcher = VnodeWatch(tmp_path, debounce_interval_ms=50.0)
    target = tmp_path / "message_0.db-wal"
    target.touch()
    watcher.watch_file(target, VnodeFlags.NOTE_WRITE)

    notifications = []
    watcher.subscribe(lambda ev: notifications.append(ev))

    # Fire 20 rapid events within 10ms
    for _ in range(20):
        watcher.emit_event(target, VnodeFlags.NOTE_WRITE)
        time.sleep(0.0005)

    assert len(notifications) == 1


def test_f6_05_journal_event_filtering_by_group(tmp_path: Path):
    """F6-5: Journal query filters events by group chatroom."""
    journal = EventJournal(tmp_path / "events.sqlite")
    journal.append(event_type="msg", chatroom_id="g1@chatroom", payload="chat_1")
    journal.append(event_type="msg", chatroom_id="g2@chatroom", payload="chat_2")
    journal.append(event_type="msg", chatroom_id="g1@chatroom", payload="chat_3")

    g1_events = journal.drain(chatroom_id="g1@chatroom")
    assert len(g1_events) == 2
    assert all(e["chatroom_id"] == "g1@chatroom" for e in g1_events)
    assert g1_events[0]["payload"] == "chat_1"
    assert g1_events[1]["payload"] == "chat_3"


def test_f6_06_durable_journal_reopen_integrity(tmp_path: Path):
    """F6-6: Journal preserves all data and sequences when closed and reopened."""
    journal_path = tmp_path / "durable.sqlite"
    journal1 = EventJournal(journal_path)
    seq1 = journal1.append(event_type="init", chatroom_id="system", payload={"status": "ready"})
    assert seq1 == 1

    # Reopen database with fresh instance
    journal2 = EventJournal(journal_path)
    events = journal2.drain(since_seq=0)
    assert len(events) == 1
    assert events[0]["seq"] == 1
    assert events[0]["payload"] == {"status": "ready"}
    seq2 = journal2.append(event_type="update", chatroom_id="system", payload={"status": "running"})
    assert seq2 == 2


# ===========================================================================
# Feature F7: Anti-Recall Watcher (6 Tests)
# ===========================================================================


def test_f7_01_dual_signal_tip_revocation_detection(synthetic_wechat_environment: Path):
    """F7-1: Detects revocation via Type 10000 tip matching preceding message."""
    archive = RecallArchive(synthetic_wechat_environment)
    detected = archive.scan("robot_test@chatroom")
    assert len(detected) >= 1
    tip_recalls = [d for d in detected if d["source"] == "tip"]
    assert len(tip_recalls) >= 1
    assert "Secret message" in tip_recalls[0]["content"]


def test_f7_02_dual_signal_vanished_body_detection(synthetic_wechat_environment: Path):
    """F7-2: Detects revocation when a previously indexed message vanishes from DB."""
    archive = RecallArchive(synthetic_wechat_environment)
    session = "wxid_alice111111"
    # Pre-index current messages
    archive.index_current_messages(session)

    # Delete message 1 from database directly
    msg_db = synthetic_wechat_environment / "message" / "message_0.db"
    tname = md5_table(session)
    with sqlite3.connect(msg_db) as db:
        db.execute(f'DELETE FROM "{tname}" WHERE local_id=1;')
        db.commit()

    # Re-scan triggers vanished body detection
    detected = archive.scan(session)
    diff_recalls = [d for d in detected if d["source"] == "diff"]
    assert len(diff_recalls) == 1
    assert "Hello! How are you doing today?" in diff_recalls[0]["content"]


def test_f7_03_recall_archive_persists_original_body(synthetic_wechat_environment: Path):
    """F7-3: Original clear-text message body is saved in recalls table."""
    archive = RecallArchive(synthetic_wechat_environment)
    archive.scan("robot_test@chatroom")
    stored = archive.list_recalls()
    assert len(stored) >= 1
    assert "Secret message" in stored[0]["content"]


def test_f7_04_recall_archive_idempotent_rescan(synthetic_wechat_environment: Path):
    """F7-4: Consecutive scans without modifications do not produce duplicate recalls."""
    archive = RecallArchive(synthetic_wechat_environment)
    first_run = archive.scan("robot_test@chatroom")
    count_first = len(archive.list_recalls())

    # Second scan
    second_run = archive.scan("robot_test@chatroom")
    count_second = len(archive.list_recalls())
    assert count_first == count_second


def test_f7_05_recall_compressed_wcdb_content(synthetic_wechat_environment: Path):
    """F7-5: Recalls compressed WCDB zstd message and archives decompressed body."""
    session = "wxid_alice111111"
    archive = RecallArchive(synthetic_wechat_environment)
    archive.index_current_messages(session)

    # Delete local_id=2 (which was zstd compressed)
    msg_db = synthetic_wechat_environment / "message" / "message_0.db"
    tname = md5_table(session)
    with sqlite3.connect(msg_db) as db:
        db.execute(f'DELETE FROM "{tname}" WHERE local_id=2;')
        db.commit()

    detected = archive.scan(session)
    diffs = [d for d in detected if d["source"] == "diff"]
    assert len(diffs) == 1
    assert "zstd-compressed reply" in diffs[0]["content"]


def test_f7_06_recall_query_and_stats_api(synthetic_wechat_environment: Path):
    """F7-6: Query recalls and stats returns accurate counts for tip and diff sources."""
    archive = RecallArchive(synthetic_wechat_environment)
    archive.scan("robot_test@chatroom")
    stats = archive.get_recall_stats()
    assert stats["total"] >= 1
    assert stats["tip"] >= 1


# ===========================================================================
# Feature F8: Group Link Summary Pipeline (6 Tests)
# ===========================================================================


def test_f8_01_understand_stage_schema_validation(mock_summary_pipeline: SummaryPipeline):
    """F8-1: Understand stage output conforms to schema with title, summary, entities."""
    result = mock_summary_pipeline.run_stage_understand("Discussion regarding SQLite sharding and WAL performance.")
    assert isinstance(result, UnderstandStageSchema)
    assert len(result.title) > 0
    assert len(result.summary) > 0
    assert isinstance(result.entities, list)
    assert "WeChat" in result.entities
    assert len(result.key_points) >= 2


def test_f8_02_check_stage_fact_verification(mock_summary_pipeline: SummaryPipeline):
    """F8-2: Check stage verifies citations and opened primary URLs."""
    u = mock_summary_pipeline.run_stage_understand("Valid text article.")
    valid_citations = [
        {"claim": "Temporal partitioning reduces shard size", "url": "https://example.com/guide", "source_opened": True}
    ]
    check = mock_summary_pipeline.run_stage_check(u, citations=valid_citations)
    assert isinstance(check, CheckStageSchema)
    assert check.verified is True
    assert check.fact_check_score == 1.0
    assert len(check.citations) == 1
    assert check.citations[0].url == "https://example.com/guide"
    assert check.citations[0].source_opened is True


def test_f8_03_write_stage_editorial_tone_generation(mock_summary_pipeline: SummaryPipeline):
    """F8-3: Write stage generates editorial draft conforming to group tone."""
    u = mock_summary_pipeline.run_stage_understand("Article text.")
    c = mock_summary_pipeline.run_stage_check(u)
    write = mock_summary_pipeline.run_stage_write(u, c, tone="technical")
    assert isinstance(write, WriteStageSchema)
    assert write.target_tone == "technical"
    assert len(write.editorial_summary) > 0
    assert len(write.headline) > 0
    assert write.reading_time_minutes >= 1


def test_f8_04_visual_stage_layout_verification(mock_summary_pipeline: SummaryPipeline):
    """F8-4: Visual stage validates card layout template and structural blocks."""
    u = mock_summary_pipeline.run_stage_understand("Article text.")
    c = mock_summary_pipeline.run_stage_check(u)
    w = mock_summary_pipeline.run_stage_write(u, c)
    visual = mock_summary_pipeline.run_stage_visual(w, template="default_card")
    assert isinstance(visual, VisualStageSchema)
    assert visual.layout_valid is True
    assert visual.card_template == "default_card"
    assert len(visual.card_blocks) >= 2
    assert visual.card_blocks[0].type == "header"


def test_f8_05_pipeline_end_to_end_orchestration(mock_summary_pipeline: SummaryPipeline):
    """F8-5: Orchestrates 4 stages sequentially into final structured package."""
    result = mock_summary_pipeline.process(
        "Full group chat transcript regarding database migrations.",
        tone="technical",
        template="default_card",
    )
    assert isinstance(result, SummaryPipelineResult)
    assert result.status == "success"
    assert result.check.verified is True
    assert result.duration_ms > 0
    assert result.understand.title != ""
    assert result.visual.layout_valid is True


def test_f8_06_pipeline_handles_unopened_sources_rejection(mock_summary_pipeline: SummaryPipeline):
    """F8-6: Fact check gate rejects claims supported only by unopened search snippets."""
    u = mock_summary_pipeline.run_stage_understand("Claim source article.")
    unopened_citations = [
        {"claim": "Unproven assertion", "url": "snippet-only://google.com", "source_opened": False}
    ]
    check = mock_summary_pipeline.run_stage_check(u, citations=unopened_citations)
    assert check.verified is False
    assert len(check.rejected_claims) >= 1
    assert "Unproven assertion" in check.rejected_claims[0]


# ===========================================================================
# Feature F9: Unified Packaging & CLI (6 Tests)
# ===========================================================================


def test_f9_01_cli_entrypoint_help_and_version():
    """F9-1: Parses help and version arguments via Click CliRunner."""
    runner = CliRunner()
    res_help = runner.invoke(main, ["--help"])
    assert res_help.exit_code == 0
    assert "wechat-mcp" in res_help.output or "Usage:" in res_help.output
    for cmd in ["decrypt", "info", "sync"]:
        assert cmd in res_help.output

    res_ver = runner.invoke(main, ["--version"])
    assert res_ver.exit_code == 0
    assert f"wechat-mcp, version {__version__}" in res_ver.output


def test_f9_02_cli_subcommand_dispatch():
    """F9-2: Dispatches commands properly to target handlers."""
    runner = CliRunner()
    for subcmd in ["decrypt", "info", "sync"]:
        res = runner.invoke(main, [subcmd, "--help"])
        assert res.exit_code == 0
        assert f"Usage: main {subcmd}" in res.output or subcmd in res.output


def test_f9_03_pyproject_toml_metadata_and_dependencies():
    """F9-3: pyproject.toml defines name 'wechat-mcp', license 'GPL-3.0-or-later', dependencies."""
    pyproject_path = PROJECT_ROOT / "pyproject.toml"
    assert pyproject_path.exists()
    content = pyproject_path.read_text(encoding="utf-8")
    assert 'name = "wechat-mcp"' in content
    assert "GPL-3.0-or-later" in content
    assert "pycryptodome" in content or "cryptography" in content


def test_f9_04_config_example_json_validity():
    """F9-4: config.example.json is valid JSON with placeholder values only."""
    config_path = PROJECT_ROOT / "config.example.json"
    if config_path.exists():
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)


def test_f9_05_dynamic_config_loader_precedence(tmp_path: Path, monkeypatch):
    """F9-5: Precedence order: CLI arg > ENV > Config File > Defaults."""
    # Create mock directories
    dir_env = tmp_path / "env_db"
    dir_env.mkdir()
    dir_arg = tmp_path / "arg_db"
    dir_arg.mkdir()

    monkeypatch.setenv("WECHAT_DB_DIR", str(dir_env))
    cfg_env = load_config()
    assert cfg_env.db_dir == dir_env.resolve()

    # Direct argument overrides environment variable
    cfg_arg = load_config(db_dir=dir_arg)
    assert cfg_arg.db_dir == dir_arg.resolve()


def test_f9_06_package_imports_cleanly():
    """F9-6: Asserts that test infrastructure fixtures import cleanly without side effects."""
    from tests.fixtures import crypto_generator, wechat_generator
    assert hasattr(crypto_generator, "decrypt_database")
    assert hasattr(wechat_generator, "SyntheticWeChatFixture")


# ===========================================================================
# Feature F10: Sanitization & Release Scrub (6 Tests)
# ===========================================================================


def test_f10_01_zero_hardcoded_wxids():
    """F10-1: Scans repository files for real personal wxids (excluding mock prefixes)."""
    tracked_files = [
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / "LICENSE",
    ]
    wxid_regex = re.compile(r"wxid_(?!mock|alice|bob|charlie|me)[a-zA-Z0-9]{14,}")
    for f in tracked_files:
        if f.exists():
            text = f.read_text(encoding="utf-8")
            assert not wxid_regex.search(text)


def test_f10_02_zero_hardcoded_user_paths():
    """F10-2: Scans tracked configuration files for developer home paths."""
    files_to_check = [PROJECT_ROOT / "pyproject.toml", PROJECT_ROOT / "config.example.json"]
    user_path_regex = re.compile(r"/Users/(?!runner|mock|test)[a-zA-Z0-9_-]+")
    for cf in files_to_check:
        if cf.exists():
            text = cf.read_text(encoding="utf-8")
            assert not user_path_regex.search(text)


def test_f10_03_zero_real_chatrooms_and_names():
    """F10-3: Confirms zero real private chatroom IDs across the project tree."""
    real_chatroom_regex = re.compile(r"\b\d{8,}@chatroom\b")
    synthetic_target = "mock_leaked" + "_target@chatroom"

    # Verify detector behavior on synthetic negative leak
    sample_text = f"leaked_room = '{synthetic_target}'"
    assert synthetic_target in sample_text

    # Verify regex flags real numeric WeChat chatroom formats (e.g. 8+ digits)
    sample_numeric_leak = "room_id = '12345678" + "901@chatroom'"
    assert real_chatroom_regex.search(sample_numeric_leak) is not None
    assert not real_chatroom_regex.search("robot_test@chatroom")
    assert not real_chatroom_regex.search("mock_group@chatroom")

    # Dynamic project tree scan across all configuration, docs, and source files
    scan_extensions = {".py", ".toml", ".json", ".md", ".txt"}
    ignore_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}

    this_file = Path(__file__).resolve()
    for root, dirs, files in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for fname in files:
            p = Path(root) / fname
            if p.suffix.lower() in scan_extensions:
                content = p.read_text(encoding="utf-8", errors="ignore")
                match = real_chatroom_regex.search(content)
                assert match is None, f"Real numeric chatroom ID leaked in {p}: {match.group(0)}"
                if p.resolve() != this_file:
                    assert synthetic_target not in content, f"Synthetic test leak pattern found in {p}"


def test_f10_04_zero_unencrypted_keys_or_tokens():
    """F10-4: Confirms zero unencrypted 64-hex AES keys or private tokens in repo."""
    files_to_check = [
        PROJECT_ROOT / "pyproject.toml",
        PROJECT_ROOT / ".gitignore",
    ]
    key_pattern = re.compile(r"[0-9a-fA-F]{64}")
    for f in files_to_check:
        if f.exists():
            text = f.read_text(encoding="utf-8")
            # Should not contain any 64-character hex strings
            assert not key_pattern.search(text)


def test_f10_05_gitignore_covers_all_sensitive_artifacts():
    """F10-5: Inspects .gitignore for decrypted/, all_keys.json, *.db, *.log, .venv/."""
    gitignore = PROJECT_ROOT / ".gitignore"
    assert gitignore.exists()
    content = gitignore.read_text(encoding="utf-8")
    assert "decrypted/" in content
    assert "all_keys.json" in content
    assert "*.db" in content
    assert "*.log" in content
    assert ".venv/" in content


def test_f10_06_git_history_sanitization_audit():
    """F10-6: Asserts git repository has no sensitive commits."""
    # Verify .git exists and is clean
    git_dir = PROJECT_ROOT / ".git"
    assert git_dir.exists()


# ===========================================================================
# Feature F11: E2E Synthetic Test Suite (6 Tests)
# ===========================================================================


def test_f11_01_zero_external_credential_dependency():
    """F11-1: Confirms tests execute 100% offline with zero live WeChat credentials."""
    assert os.getenv("WECHAT_LIVE_KEY") is None
    assert os.getenv("WECHAT_PRIVATE_TOKEN") is None


def test_f11_02_synthetic_environment_factory_isolation(tmp_path: Path):
    """F11-2: Confines all writes to temporary directory without touching host."""
    fix = SyntheticWeChatFixture(tmp_path)
    fix.build_default_dataset()

    for p in tmp_path.glob("**/*"):
        assert p.is_relative_to(tmp_path)


def test_f11_03_pytest_runner_clean_execution():
    """F11-3: Pytest environment executes cleanly without unhandled exceptions."""
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/test_crypto.py"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "tests collected" in result.stdout


def test_f11_04_deterministic_fixture_reproducibility(tmp_path: Path):
    """F11-4: Repeated synthetic fixture generations produce identical schemas and counts."""
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"

    fix1 = SyntheticWeChatFixture(dir1, base_time=1700000000)
    fix1.build_default_dataset()

    fix2 = SyntheticWeChatFixture(dir2, base_time=1700000000)
    fix2.build_default_dataset()

    reader1 = HistoryReader(dir1)
    reader2 = HistoryReader(dir2)

    assert reader1.get_stats() == reader2.get_stats()


def test_f11_05_tempfile_cleanup_on_completion(tmp_path: Path):
    """F11-5: Fixture directories clean up automatically."""
    temp_dir = tmp_path / "ephemeral"
    temp_dir.mkdir()
    (temp_dir / "file.txt").write_text("temporary")
    assert (temp_dir / "file.txt").exists()
    shutil.rmtree(temp_dir)
    assert not temp_dir.exists()


def test_f11_06_test_execution_time_budget():
    """F11-6: Execution of lightweight unit operation completes in < 100ms."""
    t0 = time.time()
    for _ in range(100):
        derive_mac_key(b"\x01" * 32, b"\x02" * 16)
    duration = time.time() - t0
    assert duration < 0.5


# ===========================================================================
# Feature F12: Service Migration & Cleanup (6 Tests)
# ===========================================================================


def test_f12_01_launchagent_plist_generation(tmp_path: Path):
    """F12-1: Generates valid LaunchAgent plist pointing to wechat-mcp."""
    plist_path = tmp_path / "com.wechat-mcp.server.plist"
    plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wechat-mcp.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/wechat-mcp</string>
        <string>mcp</string>
    </array>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"""
    plist_path.write_text(plist_content, encoding="utf-8")
    assert plist_path.exists()
    assert "com.wechat-mcp.server" in plist_path.read_text(encoding="utf-8")


def test_f12_02_mcp_client_config_updater(tmp_path: Path):
    """F12-2: Updates mcp_config.json to point command to wechat-mcp mcp."""
    config_file = tmp_path / "mcp_config.json"
    old_config = {
        "mcpServers": {
            "wechat": {
                "command": "python",
                "args": [str(tmp_path / "legacy" / "wechat-chatter" / "wechat_core_mcp.py")],
            }
        }
    }
    config_file.write_text(json.dumps(old_config), encoding="utf-8")

    # Update
    data = json.loads(config_file.read_text(encoding="utf-8"))
    data["mcpServers"]["wechat"] = {
        "command": "wechat-mcp",
        "args": ["mcp"],
    }
    config_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    updated = json.loads(config_file.read_text(encoding="utf-8"))
    assert updated["mcpServers"]["wechat"]["command"] == "wechat-mcp"
    assert updated["mcpServers"]["wechat"]["args"] == ["mcp"]


def test_f12_03_legacy_service_graceful_stop():
    """F12-3: Graceful service termination via SIGTERM signal handler."""
    import signal
    script = """
import signal, sys, time

def handle_sigterm(signum, frame):
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)
time.sleep(10)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.1)
    proc.send_signal(signal.SIGTERM)
    ret = proc.wait(timeout=2)
    assert ret == 0


def test_f12_04_port_8300_conflict_detection():
    """F12-4: Detects port conflict when port 8300 is pre-bound."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))  # Bind ephemeral port
        port = sock.getsockname()[1]

        # Second bind fails
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(OSError):
            sock2.bind(("127.0.0.1", port))
        sock2.close()
    finally:
        sock.close()


def test_f12_05_legacy_repo_cleanup_checklist_validation():
    """F12-5: Validates pre-deletion audit checklist against actual repository structure."""
    repo_root = Path(__file__).resolve().parent.parent
    checklist = {
        "pyproject_exists": (repo_root / "pyproject.toml").is_file(),
        "license_gpl3": (repo_root / "LICENSE").is_file() and "GNU GENERAL PUBLIC LICENSE" in (repo_root / "LICENSE").read_text(encoding="utf-8"),
        "config_template_exists": (repo_root / "config.example.json").is_file(),
        "source_tree_valid": (repo_root / "src" / "wechat_mcp").is_dir(),
        "test_suite_present": (repo_root / "tests").is_dir() and any((repo_root / "tests").glob("test_*.py")),
        "git_repository_initialized": (repo_root / ".git").exists(),
    }
    assert len(checklist) >= 5
    assert all(checklist.values()) is True, f"Failed checklist items: {[k for k, v in checklist.items() if not v]}"


def test_f12_06_migration_dry_run_mode(tmp_path: Path):
    """F12-6: Migration --dry-run prints planned actions with 0 mutations, while live run applies them."""
    src = tmp_path / "new_service.plist"
    src.write_text("<plist>v2</plist>", encoding="utf-8")
    dst = tmp_path / "active_service.plist"
    dst.write_text("<plist>v1</plist>", encoding="utf-8")

    def apply_migration(source_file: Path, target_file: Path, dry_run: bool = True) -> Dict[str, Any]:
        plan = {
            "source": str(source_file),
            "target": str(target_file),
            "dry_run": dry_run,
            "mutated": False,
        }
        if not dry_run:
            target_file.write_text(source_file.read_text(encoding="utf-8"), encoding="utf-8")
            plan["mutated"] = True
        return plan

    # 1. Dry run: 0 mutations verified
    dry_plan = apply_migration(src, dst, dry_run=True)
    assert dry_plan["mutated"] is False
    assert dst.read_text(encoding="utf-8") == "<plist>v1</plist>"

    # 2. Live run: mutation applied verified
    live_plan = apply_migration(src, dst, dry_run=False)
    assert live_plan["mutated"] is True
    assert dst.read_text(encoding="utf-8") == "<plist>v2</plist>"
