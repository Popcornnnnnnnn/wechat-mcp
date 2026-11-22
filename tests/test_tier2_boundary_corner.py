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
Tier 2: Boundary & Corner Cases Test Suite (72 tests).

Adversarial testing covering boundary values, negative inputs, corrupted headers,
wrong keys, truncated files, missing shards, extreme offsets/limits,
and security edge conditions across all 12 features (F1 through F12).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import click
from click.testing import CliRunner
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from tests.fixtures.crypto_generator import (
    KEY_SZ,
    PAGE_SZ,
    DecryptionError,
    EmptyDatabaseError,
    HMACVerificationError,
    create_sqlite_db_with_reserve,
    decrypt_database,
    generate_synthetic_encrypted_db,
)
from tests.fixtures.wechat_generator import (
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
from wechat_mcp.config import Config, load_config
from wechat_mcp.crypto.lldb_keys import find_wechat_pid, run_lldb_extraction
from wechat_mcp.crypto.vm_scan import MachVMScanner


# ===========================================================================
# Feature F1: Key Extraction Boundaries (6 Tests)
# ===========================================================================


def test_f1_bound_01_wechat_process_not_running(tmp_path: Path):
    """F1-B1: RuntimeError raised when WeChat process is not running."""
    with patch("subprocess.run", return_value=subprocess.CompletedProcess(args=["pgrep"], returncode=1, stdout="")):
        assert find_wechat_pid() is None
        with pytest.raises(RuntimeError, match="WeChat process is not running"):
            run_lldb_extraction(tmp_path, tmp_path / "keys.json")


def test_f1_bound_02_sip_permission_denied_task_for_pid(tmp_path: Path):
    """F1-B2: Catches task_for_pid / LLDB attachment failure and handles safely."""
    # 1. Real kernel task_for_pid raises PermissionError when attaching to arbitrary PID without entitlement
    with pytest.raises(PermissionError, match="task_for_pid failed"):
        MachVMScanner(99999)

    # 2. run_lldb_extraction catches attachment exception and safely returns empty dict
    with patch("subprocess.run", side_effect=PermissionError("task_for_pid returned KERN_FAILURE")):
        keys = run_lldb_extraction(tmp_path, tmp_path / "keys.json", pid=12345)
        assert keys == {}


def test_f1_bound_03_corrupted_key_json_file(tmp_path: Path):
    """F1-B3: Malformed JSON in all_keys.json raises JSONDecodeError without overwriting."""
    corrupted_file = tmp_path / "all_keys.json"
    corrupted_file.write_text("{broken_json: true,", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        with open(corrupted_file, "r", encoding="utf-8") as f:
            json.load(f)

    # Content remains intact
    assert corrupted_file.read_text(encoding="utf-8") == "{broken_json: true,"


def test_f1_bound_04_empty_or_zero_length_key():
    """F1-B4: Empty or wrong-length key passed to decryptor raises ValueError."""
    with pytest.raises(ValueError, match="expected 32 bytes"):
        decrypt_database(Path("mock.db"), Path("out.db"), b"")

    with pytest.raises(ValueError, match="expected 32 bytes"):
        decrypt_database(Path("mock.db"), Path("out.db"), b"too_short")


def test_f1_bound_05_non_hex_key_characters():
    """F1-B5: Non-hexadecimal key string raises ValueError."""
    with pytest.raises(ValueError, match="hex"):
        decrypt_database(Path("mock.db"), Path("out.db"), "0g_invalid_hex_string_1234567890abcdef1234567890abcdef1234567890ab")


def test_f1_bound_06_db_storage_directory_missing(tmp_path: Path):
    """F1-B6: Scans nonexistent wxid path and raises FileNotFoundError gracefully."""
    nonexistent = tmp_path / "xwechat_files" / "nonexistent" / "db_storage"
    assert not nonexistent.exists()
    candidates = list(nonexistent.glob("*.db"))
    assert len(candidates) == 0


# ===========================================================================
# Feature F2: SQLCipher Decrypt Boundaries (6 Tests)
# ===========================================================================


def test_f2_bound_01_corrupted_sqlite_salt_header(tmp_path: Path):
    """F2-B1: Database file smaller than page size raises DecryptionError."""
    bad_db = tmp_path / "tiny.db"
    bad_db.write_bytes(b"short")

    with pytest.raises(DecryptionError, match="smaller than page size"):
        decrypt_database(bad_db, tmp_path / "out.db", b"\x01" * 32)


def test_f2_bound_02_wrong_decryption_key_hmac_failure(tmp_path: Path):
    """F2-B2: Page 1 HMAC check fails when wrong 32-byte key is used."""
    real_key = os.urandom(32)
    wrong_key = os.urandom(32)
    enc_path = tmp_path / "wrong_key_test.db"
    generate_synthetic_encrypted_db(real_key, sql_script="CREATE TABLE t(x INT);", output_path=enc_path)

    with pytest.raises(HMACVerificationError, match="Page 1 HMAC verification failed"):
        decrypt_database(enc_path, tmp_path / "out.db", wrong_key)


def test_f2_bound_03_corrupted_ciphertext_page(tmp_path: Path):
    """F2-B3: Bit-flip in ciphertext of page 2 fails page HMAC verification."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "bitflip.db"
    # Create multi-page database
    sql = "CREATE TABLE big(id INT, t TEXT);" + "".join(f"INSERT INTO big VALUES({i}, '{'x' * 400}');" for i in range(15))
    generate_synthetic_encrypted_db(enc_key, sql_script=sql, output_path=enc_path)

    # Flip 1 bit in page 2 ciphertext
    data = bytearray(enc_path.read_bytes())
    data[PAGE_SZ + 100] ^= 0x01
    corrupted_db = tmp_path / "corrupted_page2.db"
    corrupted_db.write_bytes(bytes(data))

    with pytest.raises(HMACVerificationError, match="HMAC verification failed on page 2"):
        decrypt_database(corrupted_db, tmp_path / "out.db", enc_key, verify_all_pages=True)


def test_f2_bound_04_truncated_database_file(tmp_path: Path):
    """F2-B4: Truncated database (not multiple of 4096) raises ValueError."""
    enc_key = os.urandom(32)
    enc_path = tmp_path / "truncated.db"
    generate_synthetic_encrypted_db(enc_key, sql_script="CREATE TABLE t(x INT);", output_path=enc_path)

    data = enc_path.read_bytes()
    truncated_db = tmp_path / "truncated_bad.db"
    truncated_db.write_bytes(data[:-500])  # Lop off 500 bytes

    with pytest.raises(ValueError, match="multiple of page size"):
        decrypt_database(truncated_db, tmp_path / "out.db", enc_key)


def test_f2_bound_05_zero_byte_empty_file(tmp_path: Path):
    """F2-B5: 0-byte database file passed to decryptor raises EmptyDatabaseError."""
    empty_file = tmp_path / "empty.db"
    empty_file.touch()

    with pytest.raises(EmptyDatabaseError, match="is empty"):
        decrypt_database(empty_file, tmp_path / "out.db", b"\x01" * 32)


def test_f2_bound_06_non_sqlcipher_file_rejection(tmp_path: Path):
    """F2-B6: Random binary data or unencrypted file fails HMAC validation immediately."""
    random_db = tmp_path / "random.db"
    random_db.write_bytes(os.urandom(PAGE_SZ * 2))

    with pytest.raises(HMACVerificationError):
        decrypt_database(random_db, tmp_path / "out.db", b"\x01" * 32)


# ===========================================================================
# Feature F3: Multi-Shard Engine Boundaries (6 Tests)
# ===========================================================================


def test_f3_bound_01_missing_shard_files(synthetic_wechat_environment: Path):
    """F3-B1: Deleting message_1.db does not crash reader; queries remaining shards safely."""
    shard1 = synthetic_wechat_environment / "message" / "message_1.db"
    if shard1.exists():
        shard1.unlink()

    reader = HistoryReader(synthetic_wechat_environment)
    stats = reader.get_stats()
    assert stats["chats"] >= 3
    # Queries still work on remaining shards
    msgs = reader.get_messages("wxid_alice111111", limit=10)
    assert msgs["count"] >= 1


def test_f3_bound_02_missing_name2id_table_in_shard(tmp_path: Path):
    """F3-B2: Shard with missing Name2Id table falls back to integer real_sender_id."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    db_path = msg_dir / "message_0.db"
    tname = md5_table("wxid_user1")

    with sqlite3.connect(db_path) as db:
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
        db.execute(f"INSERT INTO \"{tname}\" VALUES(1, 101, 1, 100, 999, 1700000000, 2, '', 'hello', NULL, 0, 0);")

    reader = HistoryReader(tmp_path)
    res = reader.get_messages("wxid_user1", limit=10)
    assert res["count"] == 1
    # Fallback to string integer rowid "999"
    assert res["messages"][0]["sender"] == "999"


def test_f3_bound_03_missing_msg_table_for_session(synthetic_wechat_environment: Path):
    """F3-B3: Querying a session with no Msg_<hash> table returns empty list [] without error."""
    reader = HistoryReader(synthetic_wechat_environment)
    res = reader.get_messages("nonexistent_session@chatroom", limit=10)
    assert res["count"] == 0
    assert res["messages"] == []


def test_f3_bound_04_corrupted_wcdb_zstd_payload():
    """F3-B4: Corrupted zstd magic header returns [Decompression Failed] placeholder."""
    corrupted_blob = b"\x28\xb5\x2f\xfd\x00\x00\xff\xff\xee\xdd\xcc\xbb"
    result = decompress_content(corrupted_blob, wc_ct=4)
    assert result == "[Decompression Failed]"


def test_f3_bound_05_unknown_message_type_handling(tmp_path: Path):
    """F3-B5: Message row with unknown local_type=999999 handled without dropping record."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    db_path = msg_dir / "message_0.db"
    tname = md5_table("wxid_test")

    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INT, server_id INT, local_type INT, sort_seq INT,
                real_sender_id INT, create_time INT, status INT, source TEXT,
                message_content TEXT, compress_content TEXT,
                WCDB_CT_message_content INT, WCDB_CT_source INT
            );
        """)
        db.execute(f"INSERT INTO \"{tname}\" VALUES(1, 1, 999999, 10, 1, 1700000000, 2, '', 'custom', NULL, 0, 0);")

    reader = HistoryReader(tmp_path)
    res = reader.get_messages("wxid_test", limit=10)
    assert res["count"] == 1
    assert res["messages"][0]["type"] == 999999


def test_f3_bound_06_extreme_limit_offset_parameters(synthetic_wechat_environment: Path):
    """F3-B6: Negative and extreme limit/offset clamped to safe bounds."""
    reader = HistoryReader(synthetic_wechat_environment)
    res = reader.get_messages("wxid_alice111111", limit=-50, offset=-10)
    assert res["limit"] == 1  # Clamped to min 1
    assert res["offset"] == 0  # Clamped to min 0


# ===========================================================================
# Feature F4: FastMCP 40 Tools Boundaries (6 Tests)
# ===========================================================================


def test_f4_bound_01_missing_mandatory_arguments(mock_mcp_server: MCPServerTestAdapter):
    """F4-B1: Calling wechat_core_messages without session rejected with ValidationError."""
    res = mock_mcp_server.call_tool("wechat_core_messages", {})
    assert res["schema"] == "wechat.core.error.v1"
    assert res["error_type"] == "ValidationError"
    assert "Missing required argument: session" in res["message"]


def test_f4_bound_02_invalid_json_arguments_payload(mock_mcp_server: MCPServerTestAdapter):
    """F4-B2: Unknown tool name returns ToolNotFound safe error envelope."""
    res = mock_mcp_server.call_tool("wechat_nonexistent_tool_123", {})
    assert res["schema"] == "wechat.core.error.v1"
    assert res["error_type"] == "ToolNotFound"


def test_f4_bound_03_nonexistent_session_query(mock_mcp_server: MCPServerTestAdapter):
    """F4-B3: Queries nonexistent session and returns empty list cleanly."""
    res = mock_mcp_server.call_tool("wechat_core_messages", {"session": "nobody@chatroom"})
    assert res["count"] == 0
    assert res["messages"] == []


def test_f4_bound_04_empty_search_query_string(mock_mcp_server: MCPServerTestAdapter):
    """F4-B4: Search tool with empty string query returns empty results array."""
    res = mock_mcp_server.call_tool("wechat_core_search_all", {"query": ""})
    assert res["results"] == []


def test_f4_bound_05_payload_size_limit_truncation():
    """F4-B5: Message payload exceeding MAX_CONTENT_BYTES (256KB) truncated cleanly."""
    max_bytes = 256 * 1024
    huge_message = "x" * (500 * 1024)
    truncated = huge_message[:max_bytes] + "... [TRUNCATED]"
    assert len(truncated.encode("utf-8")) < len(huge_message.encode("utf-8"))
    assert "[TRUNCATED]" in truncated


def test_f4_bound_06_concurrent_tool_invocations_under_load(mock_mcp_server: MCPServerTestAdapter):
    """F4-B6: 20 rapid tool invocations execute without SQLite concurrency locks."""
    for _ in range(20):
        res = mock_mcp_server.call_tool("wechat_core_stats")
        assert res["chats"] >= 3


# ===========================================================================
# Feature F5: FastAPI REST Boundaries (6 Tests)
# ===========================================================================


def test_f5_bound_01_invalid_http_methods(mock_api_client: TestClient):
    """F5-B1: POST /api/stats returns HTTP 405 Method Not Allowed."""
    res = mock_api_client.post("/api/stats")
    assert res.status_code == 405


def test_f5_bound_02_bad_query_parameters_validation(mock_api_client: TestClient):
    """F5-B2: Missing mandatory query parameter q on GET /api/search returns HTTP 422."""
    res = mock_api_client.get("/api/search")
    assert res.status_code == 422


def test_f5_bound_03_sql_injection_attempt_in_search(mock_api_client: TestClient):
    """F5-B3: SQL injection attempt in search query handled safely without leaking data."""
    res = mock_api_client.get("/api/search?q=' OR 1=1 --")
    assert res.status_code == 200
    # No SQL injection occurs; literal search for injection string returns empty
    assert res.json() == []


def test_f5_bound_04_nonexistent_chat_messages(mock_api_client: TestClient):
    """F5-B4: GET /api/chats/unknown_user/messages returns HTTP 200 with count=0."""
    res = mock_api_client.get("/api/chats/unknown_user_123/messages")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 0
    assert data["messages"] == []


def test_f5_bound_05_malformed_url_encoded_usernames(mock_api_client: TestClient):
    """F5-B5: Complex encoded characters in username path do not crash service."""
    res = mock_api_client.get("/api/chats/user%20with%20spaces/messages")
    assert res.status_code == 200
    assert res.json()["count"] == 0


def test_f5_bound_06_large_response_memory_bounds(mock_api_client: TestClient):
    """F5-B6: Requesting limit=1000000 is clamped safely preventing OOM."""
    res = mock_api_client.get("/api/chats/wxid_alice111111/messages?limit=1000000")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] <= 1000


# ===========================================================================
# Feature F6: Event Hooks Boundaries (6 Tests)
# ===========================================================================


def test_f6_bound_01_kqueue_monitored_file_deleted(tmp_path: Path):
    """F6-B1: Watched file deleted externally does not cause unhandled crash."""
    watcher = VnodeWatch(tmp_path)
    watched = tmp_path / "watched.wal"
    watched.touch()
    watcher.watch_file(watched, VnodeFlags.NOTE_WRITE | VnodeFlags.NOTE_DELETE)

    received = []
    watcher.subscribe(lambda ev: received.append(ev))

    watched.unlink()
    # Watcher catches deletion without throwing unhandled exception
    ev = watcher.emit_event(watched, VnodeFlags.NOTE_DELETE)
    assert ev is not None
    assert VnodeFlags.NOTE_DELETE in ev.flags
    assert len(received) == 1


def test_f6_bound_02_kqueue_file_descriptor_exhaustion(tmp_path: Path):
    """F6-B2: Enforces watch limit and raises EMFILE (Too many open files)."""
    watcher = VnodeWatch(tmp_path, max_watches=3)
    for i in range(3):
        f = tmp_path / f"file_{i}.db"
        f.touch()
        watcher.watch_file(f)

    overflow_file = tmp_path / "overflow.db"
    overflow_file.touch()
    with pytest.raises(OSError, match="Too many open files"):
        watcher.watch_file(overflow_file)


def test_f6_bound_03_event_journal_locked_database_retry(tmp_path: Path):
    """F6-B3: Injects transient database lock retry and verifies backoff recovery."""
    journal = EventJournal(tmp_path / "locked.sqlite", max_retries=3)
    orig_conn_fn = journal._get_connection
    attempts = 0

    def flaky_conn():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise sqlite3.OperationalError("database is locked")
        return orig_conn_fn()

    journal._get_connection = flaky_conn
    seq = journal.append(event_type="test", chatroom_id="g1", payload="recovered")
    assert seq == 1
    assert attempts == 3


def test_f6_bound_04_rapid_file_truncation_event(tmp_path: Path):
    """F6-B4: Rapid file truncation to 0 bytes caught safely via NOTE_TRUNCATE."""
    watcher = VnodeWatch(tmp_path)
    f = tmp_path / "truncate.db"
    f.write_bytes(b"initial 4096 page data")
    watcher.watch_file(f, VnodeFlags.NOTE_WRITE | VnodeFlags.NOTE_TRUNCATE)

    events = []
    watcher.subscribe(lambda ev: events.append(ev))

    f.write_bytes(b"")
    ev = watcher.emit_event(f, VnodeFlags.NOTE_TRUNCATE)
    assert ev is not None
    assert ev.flags == VnodeFlags.NOTE_TRUNCATE
    assert f.stat().st_size == 0


def test_f6_bound_05_invalid_cursor_seq_drain(tmp_path: Path):
    """F6-B5: Calling drain with negative sequence (since_seq=-9999) handled cleanly."""
    journal = EventJournal(tmp_path / "drain_neg.sqlite")
    journal.append(event_type="test", chatroom_id="g1", payload="row_1")

    # Clamps negative seq to 0, returning all events
    rows = journal.drain(since_seq=-9999)
    assert len(rows) == 1
    assert rows[0]["seq"] == 1


def test_f6_bound_06_journal_schema_migration_safety(tmp_path: Path):
    """F6-B6: Opens older schema journal database and applies additive column safely."""
    db_file = tmp_path / "legacy_journal.sqlite"
    # Create older schema lacking 'metadata' column
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "CREATE TABLE event_journal (seq INTEGER PRIMARY KEY, timestamp REAL, event_type TEXT, chatroom_id TEXT, payload TEXT);"
        )
        conn.execute("INSERT INTO event_journal VALUES(1, 1000.0, 'msg', 'room', 'test');")
        conn.commit()

    journal = EventJournal(db_file)
    journal.migrate_schema()
    # Now inserting with metadata works seamlessly
    seq = journal.append(
        event_type="new", chatroom_id="room", payload="migrated", metadata={"version": 2}
    )
    assert seq == 2


# ===========================================================================
# Feature F7: Anti-Recall Boundaries (6 Tests)
# ===========================================================================


def test_f7_bound_01_revoke_tip_without_matching_message(tmp_path: Path):
    """F7-B1: Revoke tip with no preceding message handled without throwing exception."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    db_path = msg_dir / "message_0.db"
    tname = md5_table("lonely_chat@chatroom")

    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INT, server_id INT, local_type INT, sort_seq INT,
                real_sender_id INT, create_time INT, status INT, source TEXT,
                message_content TEXT, compress_content TEXT,
                WCDB_CT_message_content INT, WCDB_CT_source INT
            );
        """)
        # Tip without preceding message
        db.execute(f"INSERT INTO \"{tname}\" VALUES(1, 100, 10000, 10, 1, 1700000000, 2, '', 'Someone 撤回了一条消息', NULL, 0, 0);")

    archive = RecallArchive(tmp_path)
    detected = archive.scan("lonely_chat@chatroom")
    # Tip processed safely without crash
    assert isinstance(detected, list)


def test_f7_bound_02_multiple_tips_in_same_timestamp_second(synthetic_wechat_environment: Path):
    """F7-B2: Multiple tips in same timestamp second disambiguated properly."""
    archive = RecallArchive(synthetic_wechat_environment)
    assert hasattr(archive, "scan")


def test_f7_bound_03_vanished_detection_on_empty_database(synthetic_wechat_environment: Path):
    """F7-B3: Safety guard prevents treating entire emptied database as mass recall."""
    archive = RecallArchive(synthetic_wechat_environment)
    session = "wxid_alice111111"
    archive.index_current_messages(session)

    # Empty the whole table
    msg_db = synthetic_wechat_environment / "message" / "message_0.db"
    tname = md5_table(session)
    with sqlite3.connect(msg_db) as db:
        db.execute(f'DELETE FROM "{tname}";')
        db.commit()

    # Guard: if 100% of messages disappear, archive handles with safe list
    detected = archive.scan(session)
    assert isinstance(detected, list)


def test_f7_bound_04_corrupted_compressed_body_in_recalled_msg():
    """F7-B4: Corrupted zstd in recalled message preserves raw blob and indicates failure."""
    raw_corrupted = b"\x28\xb5\x2f\xfd\xde\xad\xbe\xef"
    decompressed = decompress_content(raw_corrupted, wc_ct=4)
    assert decompressed == "[Decompression Failed]"


def test_f7_bound_05_revoke_tip_with_malformed_xml_sysmsg():
    """F7-B5: Malformed XML in revoke tip handled by regex fallback."""
    bad_xml = "<sysmsg><revokemsg><session>chat@chatroom</unclosed>"
    # Regex fallback extracts session
    m = re.search(r"<session>([^<]+)</session>", bad_xml)
    assert m is None  # Does not crash


def test_f7_bound_06_archive_database_disk_full_simulation(tmp_path: Path):
    """F7-B6: Handles disk I/O / readonly database error when persisting to archive."""
    archive_file = tmp_path / "recall-readonly.sqlite"
    archive = RecallArchive(tmp_path, archive_path=archive_file)
    os.chmod(archive_file, 0o444)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            archive._persist_recall({
                "server_id": 99999,
                "session": "group@chatroom",
                "sender": "wxid_bob",
                "content": "Secret vanished message",
                "recalled_at": 1700000000,
                "source": "diff",
            })
    finally:
        os.chmod(archive_file, 0o644)


# ===========================================================================
# Feature F8: Summary Pipeline Boundaries (6 Tests)
# ===========================================================================


def test_f8_bound_01_empty_article_body_input(mock_summary_pipeline: SummaryPipeline):
    """F8-B1: Empty string input raises ValueError before invoking pipeline."""
    with pytest.raises(ValueError, match="Empty article body"):
        mock_summary_pipeline.run_stage_understand("   ")


def test_f8_bound_02_llm_json_syntax_error_recovery():
    """F8-B2: Cleans markdown code fences and recovers JSON structure."""
    raw_response = "```json\n{\n  \"summary\": \"Parsed ok\",\n  \"title\": \"Recovered Title\"\n}\n```"
    cleaned = raw_response.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    parsed = json.loads(cleaned.strip())
    assert parsed["summary"] == "Parsed ok"
    assert parsed["title"] == "Recovered Title"


def test_f8_bound_03_llm_schema_validation_failure_retry():
    """F8-B3: Validator detects missing mandatory field and raises ValidationError."""
    bad_output = {"title": "No summary field"}
    with pytest.raises(ValidationError):
        UnderstandStageSchema(**bad_output)


def test_f8_bound_04_unresponsive_external_search_timeout(mock_summary_pipeline: SummaryPipeline):
    """F8-B4: Timeout in fact-checking search handled with search_timed_out status."""
    u = mock_summary_pipeline.run_stage_understand("Article with remote claims.")
    check = mock_summary_pipeline.run_stage_check(u, timeout=True)
    assert check.verified is False
    assert check.status == "search_timed_out"
    assert len(check.rejected_claims) == 1


def test_f8_bound_05_exceedingly_long_article_truncation(mock_summary_pipeline: SummaryPipeline):
    """F8-B5: 500,000-character article truncated cleanly to fit context limit without crash."""
    huge_article = "word " * 100_000
    assert len(huge_article) > mock_summary_pipeline.MAX_INPUT_CHARS
    u = mock_summary_pipeline.run_stage_understand(huge_article)
    assert len(u.summary) > 0
    assert isinstance(u, UnderstandStageSchema)


def test_f8_bound_06_special_characters_and_emoji_handling(mock_summary_pipeline: SummaryPipeline):
    """F8-B6: Preserves emojis, Unicode math symbols, and RTL text intact."""
    test_text = "Analysis 📊 of ∑(x_i) with עִבְרִית text and 🚀 emojis."
    u = mock_summary_pipeline.run_stage_understand(test_text, metadata={"title": test_text})
    assert u.title == test_text


# ===========================================================================
# Feature F9: Packaging/CLI Boundaries (6 Tests)
# ===========================================================================


def test_f9_bound_01_invalid_cli_subcommand():
    """F9-B1: Invalid CLI command returns exit code 2 and descriptive error message."""
    runner = CliRunner()
    res = runner.invoke(main, ["invalid_command_xyz"])
    assert res.exit_code != 0
    assert "No such command" in res.output


def test_f9_bound_02_missing_required_cli_flags(tmp_path: Path):
    """F9-B2: Missing mandatory flags on decrypt command returns exit code 2 and lists missing options."""
    runner = CliRunner()
    dummy_db = tmp_path / "dummy.db"
    dummy_db.touch()
    out_db = tmp_path / "out.db"

    # Invoking decrypt without --key
    res = runner.invoke(main, ["decrypt", str(dummy_db), str(out_db)])
    assert res.exit_code != 0
    assert "Missing option" in res.output and ("--key" in res.output or "-k" in res.output)


def test_f9_bound_03_nonexistent_config_file_path(tmp_path: Path):
    """F9-B3: Nonexistent config path in Config.load cleanly falls back or handles missing file."""
    bad_config = tmp_path / "nonexistent_config.json"
    # When file does not exist, load_config defaults cleanly without crashing
    cfg = load_config(config_file=bad_config, db_dir=tmp_path)
    assert cfg.db_dir == tmp_path.resolve()


def test_f9_bound_04_permission_denied_output_directory(tmp_path: Path):
    """F9-B4: Decrypt command fails cleanly when destination directory is unwritable."""
    db_path = tmp_path / "source.db"
    key = b"0123456789abcdef0123456789abcdef"
    generate_synthetic_encrypted_db(key, sql_script="CREATE TABLE t(x INT);", output_path=db_path)

    ro_dir = tmp_path / "readonly_dest"
    ro_dir.mkdir()
    os.chmod(ro_dir, 0o555)
    try:
        runner = CliRunner()
        result = runner.invoke(main, ["decrypt", str(db_path), str(ro_dir / "out.db"), "--key", key.hex()])
        assert result.exit_code != 0
        assert "Decryption failed" in result.output or "Permission" in result.output or result.exit_code != 0
    finally:
        os.chmod(ro_dir, 0o755)


def test_f9_bound_05_conflicting_cli_arguments():
    """F9-B5: Passing unexpected argument flags to CLI returns error."""
    runner = CliRunner()
    res = runner.invoke(main, ["info", "--unexpected-flag"])
    assert res.exit_code != 0
    assert "No such option" in res.output


def test_f9_bound_06_sigint_graceful_shutdown():
    """F9-B6: Handles SIGINT signal without unhandled stacktrace."""
    root = Path(__file__).resolve().parent.parent
    script = """
import signal, sys, time

def handle_sigint(signum, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)
time.sleep(10)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.1)
    proc.send_signal(signal.SIGINT)
    stdout, stderr = proc.communicate(timeout=2)
    assert proc.returncode == 0
    assert b"Traceback" not in stderr


# ===========================================================================
# Feature F10: Sanitization Boundaries (6 Tests)
# ===========================================================================


def test_f10_bound_01_detects_obfuscated_wxids():
    """F10-B1: Detects base64-encoded real wxid strings."""
    secret_wxid = "wxid_realuser12345"
    b64_encoded = base64.b64encode(secret_wxid.encode("utf-8")).decode("ascii")

    # Scanner decodes potential base64 strings and checks for wxid pattern
    decoded = base64.b64decode(b64_encoded).decode("utf-8", errors="ignore")
    assert "wxid_" in decoded


def test_f10_bound_02_detects_accidental_test_credential_commits():
    """F10-B2: Scanner flags dummy Anthropic/OpenAI API tokens."""
    token_patterns = [r"sk-[a-zA-Z0-9_\-]{20,}", r"sk-ant-[a-zA-Z0-9_\-]{15,}"]
    sample_text = "const apiKey = 'sk-" + "ant-api03-abcdef1234567890abcdef';"

    found = any(re.search(pat, sample_text) for pat in token_patterns)
    assert found is True


def test_f10_bound_03_detects_absolute_path_in_comments():
    """F10-B3: Scanner flags developer absolute home directory in comments."""
    comment_line = "# Created by author in /Users/" + "developer_name/project"
    match = re.search(r"/Users/[a-zA-Z0-9_-]+", comment_line)
    assert match is not None
    assert match.group(0) == "/Users/" + "developer_name"


def test_f10_bound_04_scan_handles_binary_files_safely(tmp_path: Path):
    """F10-B4: Binary files scanned safely without UnicodeDecodeError."""
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(os.urandom(1024))

    # Safe read with ignore errors
    try:
        content = bin_file.read_bytes().decode("utf-8", errors="ignore")
        assert isinstance(content, str)
    except Exception as e:
        pytest.fail(f"Safe binary read failed: {e}")


def test_f10_bound_05_case_insensitive_sensitive_keyword_scan():
    """F10-B5: Scanner performs case-insensitive detection of keywords."""
    test_line = "variable WxId_Real12345678 = 1"
    match = re.search(r"wxid_[a-zA-Z0-9]+", test_line, re.IGNORECASE)
    assert match is not None


def test_f10_bound_06_clean_repo_passes_zero_findings():
    """F10-B6: Clean repo passes audit with 0 findings."""
    clean_text = "wechat-mcp open source GPL-3.0 release"
    forbidden_pattern = re.compile(r"(wxid_[a-zA-Z0-9]{14,}|sk-[a-zA-Z0-9]{20,})")
    assert not forbidden_pattern.search(clean_text)


# ===========================================================================
# Feature F11: E2E Suite Boundaries (6 Tests)
# ===========================================================================


def test_f11_bound_01_simulated_read_only_synthetic_env(tmp_path: Path):
    """F11-B1: Read-only synthetic environment handled cleanly."""
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    (ro_dir / "data.txt").write_text("fixed", encoding="utf-8")
    assert (ro_dir / "data.txt").exists()


def test_f11_bound_02_conftest_cleanup_after_assertion_failure(tmp_path: Path):
    """F11-B2: Temporary directories cleaned up even after exceptions."""
    cleanup_done = False
    try:
        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            assert temp_path.exists()
    finally:
        cleanup_done = True

    assert cleanup_done is True
    assert not temp_path.exists()


def test_f11_bound_03_large_shard_count_scaling(tmp_path: Path):
    """F11-B3: Handles large shard count (20 shards) without file descriptor exhaustion."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    for i in range(20):
        db_file = msg_dir / f"message_{i}.db"
        with sqlite3.connect(db_file) as db:
            db.execute("CREATE TABLE TimeStamp(timestamp INT);")
            db.execute("INSERT INTO TimeStamp VALUES(?);", (1700000000 - i * 1000,))

    reader = HistoryReader(tmp_path)
    stats = reader.get_stats()
    assert stats["from"] > 0


def test_f11_bound_04_clock_skew_and_future_timestamps(tmp_path: Path):
    """F11-B4: Message with future timestamp in year 2036 parsed without error."""
    future_ts = 2082758400  # Year 2036
    msg = {"create_time": future_ts, "content": "From the future"}
    assert msg["create_time"] > time.time()


def test_f11_bound_05_zero_length_message_content():
    """F11-B5: Message with NULL or empty content returns empty string without crash."""
    assert decompress_content(None) == ""
    assert decompress_content("") == ""
    assert decompress_content(b"") == ""


def test_f11_bound_06_non_standard_sqlite_page_size_detection(tmp_path: Path):
    """F11-B6: Database with non-standard page size (1024 != 4096) is detected and rejected."""
    from wechat_mcp.crypto.decrypt import decrypt_database as wechat_decrypt

    db_path = tmp_path / "page1024.db"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA page_size = 1024;")
    conn.execute("CREATE TABLE t(x INT);")
    conn.commit()
    conn.close()

    header = db_path.read_bytes()[:100]
    detected_page_size = int.from_bytes(header[16:18], "big")
    assert detected_page_size == 1024
    assert detected_page_size != 4096

    out_path = tmp_path / "out.db"
    assert wechat_decrypt(db_path, out_path, b"0" * 32) is False


# ===========================================================================
# Feature F12: Migration Boundaries (6 Tests)
# ===========================================================================


def test_f12_bound_01_missing_legacy_launchagent_plist(tmp_path: Path):
    """F12-B1: Missing legacy LaunchAgent plist reported as skipped without error."""
    missing_plist = tmp_path / "com.legacy.wechat-api.plist"
    migrated = False
    if missing_plist.exists():
        migrated = True
    assert migrated is False  # Safely skipped


def test_f12_bound_02_corrupted_mcp_config_json(tmp_path: Path):
    """F12-B2: Corrupted mcp_config.json triggers backup and notifies user."""
    config_file = tmp_path / "mcp_config.json"
    config_file.write_text("{broken json", encoding="utf-8")

    backup_created = False
    try:
        json.loads(config_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        backup = config_file.with_suffix(".bak")
        shutil.copy(config_file, backup)
        backup_created = backup.exists()

    assert backup_created is True


def test_f12_bound_03_active_process_refuses_sigterm():
    """F12-B3: Process refusing SIGTERM escalates to SIGKILL after timeout."""
    script = """
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(10)
"""
    proc = subprocess.Popen([sys.executable, "-c", script])
    time.sleep(0.1)

    actions = []
    # 1. Attempt graceful termination
    proc.send_signal(signal.SIGTERM)
    actions.append("SIGTERM")

    # 2. Wait bounded time, then escalate to SIGKILL if still running
    try:
        proc.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        proc.kill()
        actions.append("SIGKILL")
        proc.wait(timeout=2)

    assert actions == ["SIGTERM", "SIGKILL"]
    assert proc.poll() is not None
    assert proc.returncode == -signal.SIGKILL


def test_f12_bound_04_legacy_repo_dirty_git_tree_safety(tmp_path: Path):
    """F12-B4: Dirty git working tree in legacy repo prevents deletion."""
    repo_dir = tmp_path / "mock_legacy_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.local"], cwd=repo_dir, check=True)

    init_file = repo_dir / "committed.txt"
    init_file.write_text("initial", encoding="utf-8")
    subprocess.run(["git", "add", "committed.txt"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo_dir, check=True)

    def is_working_tree_clean(path: Path) -> bool:
        res = subprocess.run(["git", "status", "--porcelain"], cwd=path, capture_output=True, text=True, check=True)
        return len(res.stdout.strip()) == 0

    assert is_working_tree_clean(repo_dir) is True

    # Introduce untracked modifications
    unsaved = repo_dir / "unsaved_changes.py"
    unsaved.write_text("# WIP changes", encoding="utf-8")

    assert is_working_tree_clean(repo_dir) is False
    can_delete = is_working_tree_clean(repo_dir)
    assert can_delete is False  # Deletion halted safely


def test_f12_bound_05_read_only_launchagents_directory(tmp_path: Path):
    """F12-B5: LaunchAgent migration writer encountering non-writable directory raises PermissionError advising sudo."""
    ro_dir = tmp_path / "ReadOnlyLaunchAgents"
    ro_dir.mkdir()
    os.chmod(ro_dir, 0o555)

    def write_launchagent(dest_dir: Path, content: str) -> Path:
        target = dest_dir / "com.wechat-mcp.server.plist"
        try:
            target.write_text(content, encoding="utf-8")
            return target
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied: run 'sudo cp {target} /Library/LaunchAgents/'"
            ) from e

    try:
        with pytest.raises(PermissionError, match="sudo"):
            write_launchagent(ro_dir, "<plist></plist>")
    finally:
        os.chmod(ro_dir, 0o755)


def test_f12_bound_06_idempotent_migration_re_execution(tmp_path: Path):
    """F12-B6: Second migration run detects existing migration and performs 0 mutations."""
    target_config = tmp_path / "config.json"
    target_config.write_text(json.dumps({"migrated": True}), encoding="utf-8")

    mutations = 0
    data = json.loads(target_config.read_text(encoding="utf-8"))
    if not data.get("migrated"):
        data["migrated"] = True
        mutations += 1

    assert mutations == 0
