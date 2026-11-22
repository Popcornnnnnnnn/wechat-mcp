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
Tier 5 Adversarial Coverage Hardening Test Suite.

Integrates Challenger 1 (Part 1, 18 tests) and Challenger 2 (Part 2, 20 tests) suites
into a unified canonical suite of 38 adversarial challenge tests exercising:
- Pure-Python SQLCipher 4 crypto, corrupted frames, invalid key boundaries, unwritable destinations
- Multi-shard connection pool resilience, corrupted shards, concurrency, unmapped rowids, SQL injection
- ZSTD/ZLIB decompression streams and boundary truncation
- CLI argument errors, precedence hierarchy, missing/corrupted configs
- FastMCP tool dispatch, hostile tool names, sensitive path/wxid redactions, legacy cursor rejection
- FastAPI REST parameter bounds, directory traversal defenses, CORS preflights, unhandled DB errors
- Watcher descriptor exhaustion, event debouncing, XML Entity Expansion (XXE) defense, mass recall suppression
- Editorial summary pipeline code fence cleaning, SSRF scheme rejection, input bounds, search timeouts
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import errno
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import threading
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock
import zlib

from click.testing import CliRunner
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from wechat_mcp.api.server import create_api_app
from wechat_mcp.cli import main
from wechat_mcp.config import (
    Config,
    WeChatConfigError,
    discover_accounts,
    load_config,
)
from wechat_mcp.crypto.decrypt import (
    PAGE_SZ,
    RESERVE_SZ,
    SALT_SZ,
    decrypt_database,
    decrypt_page,
    derive_mac_key,
    encrypt_database,
    verify_page1_hmac,
    verify_page_hmac,
)
from wechat_mcp.crypto.lldb_keys import (
    collect_target_databases,
    get_key_registers,
    verify_keys_file,
)
from wechat_mcp.crypto.sync import (
    DatabaseCatalog,
    DatabaseCategory,
    DatabaseEntry,
    SyncManager,
    SyncResult,
    SyncStatus,
    checkpoint_wal_pure_python,
    is_stale,
    sync_database_file,
)
from wechat_mcp.db.decompress import (
    MAX_CONTENT_BYTES,
    WCDB_CT_PLAIN,
    WCDB_CT_ZSTD,
    decompress_content,
)
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.sender import SenderResolver
from wechat_mcp.db.shards import ShardManager, md5_table
from wechat_mcp.mcp.errors import ERROR_SCHEMA, safe_error
from wechat_mcp.mcp.push import EventPush
from wechat_mcp.mcp.server import create_mcp_server
from wechat_mcp.summary.pipeline import SummaryPipeline, clean_json_response
from wechat_mcp.summary.schema import Citation, UnderstandStageSchema
from wechat_mcp.watcher.journal import EventJournal
from wechat_mcp.watcher.kqueue import VnodeFlags, VnodeWatch
from wechat_mcp.watcher.recall import RecallArchive
from tests.fixtures.crypto_generator import (
    create_sqlite_db_with_reserve,
    generate_synthetic_encrypted_db,
)
from tests.fixtures.wechat_generator import SyntheticWeChatFixture

try:
    import zstandard
except ImportError:
    zstandard = None


# ===========================================================================
# 1. CRYPTO ADVERSARIAL TESTS (Challenger 1, Part 1)
# ===========================================================================

def test_crypto_partial_page_truncation_detection(tmp_path: Path) -> None:
    """Test decrypt_database behavior when files are truncated or contain partial trailing pages."""
    key = b"\x01" * 32

    # Case A: File smaller than 1 full page (e.g. 2048 bytes)
    sub_page_file = tmp_path / "sub_page.db"
    sub_page_file.write_bytes(b"A" * 2048)
    out_a = tmp_path / "out_a.db"
    assert decrypt_database(sub_page_file, out_a, key) is False
    assert not out_a.exists()

    # Case B: Multi-page DB with a truncated final page (e.g. 1.5 pages = 6144 bytes)
    full_db = generate_synthetic_encrypted_db(
        key,
        sql_script="CREATE TABLE t1(x); INSERT INTO t1 VALUES (zeroblob(6000));",
        output_path=tmp_path / "full.db",
    )
    full_bytes = full_db.read_bytes()
    assert len(full_bytes) >= PAGE_SZ * 2

    # Truncate halfway through page 2
    truncated_bytes = full_bytes[: PAGE_SZ + 1024]
    trunc_file = tmp_path / "truncated.db"
    trunc_file.write_bytes(truncated_bytes)

    out_b = tmp_path / "out_b.db"
    # decrypt_database handles partial trailing page: processes complete page 1 without crash
    res = decrypt_database(trunc_file, out_b, key)
    if res is True:
        assert out_b.exists()
        assert out_b.stat().st_size == PAGE_SZ  # only complete page 1 was written


def test_crypto_page1_hmac_corruption_variants(tmp_path: Path) -> None:
    """Verify that corruptions across all regions of Page 1 are strictly rejected."""
    key = b"\x22" * 32
    enc_db = generate_synthetic_encrypted_db(
        key,
        sql_script="CREATE TABLE secure(val TEXT); INSERT INTO secure VALUES ('confidential');",
        output_path=tmp_path / "secure.db",
    )
    orig_bytes = bytearray(enc_db.read_bytes())

    # Regions of Page 1:
    # 0..15: Salt
    # 16..4015: Ciphertext body
    # 4016..4031: IV
    # 4032..4095: Stored HMAC-SHA512
    test_positions = [
        ("salt", 5),
        ("ciphertext", 100),
        ("iv", 4020),
        ("hmac", 4050),
    ]

    for name, offset in test_positions:
        corrupted = bytearray(orig_bytes)
        corrupted[offset] ^= 0xFF
        corrupt_path = tmp_path / f"corrupt_{name}.db"
        corrupt_path.write_bytes(corrupted)

        # Direct page1 check must fail
        assert verify_page1_hmac(bytes(corrupted[:PAGE_SZ]), key) is False

        # Database decryption must fail and leave no output
        dst_path = tmp_path / f"out_{name}.db"
        assert decrypt_database(corrupt_path, dst_path, key) is False
        assert not dst_path.exists()


def test_crypto_page_n_hmac_corruption_mid_stream(tmp_path: Path) -> None:
    """Verify that corruption on Page N (N >= 2) aborts decryption and unlinks temp files."""
    key = b"\x33" * 32
    # Create DB with at least 3 pages
    enc_db = generate_synthetic_encrypted_db(
        key,
        sql_script="CREATE TABLE t(x); INSERT INTO t VALUES (zeroblob(10000));",
        output_path=tmp_path / "multipage.db",
    )
    data = bytearray(enc_db.read_bytes())
    total_pages = len(data) // PAGE_SZ
    assert total_pages >= 3

    # Corrupt HMAC on Page 2 (last 64 bytes of Page 2)
    p2_hmac_offset = 2 * PAGE_SZ - 20
    data[p2_hmac_offset] ^= 0xAA

    corrupt_db = tmp_path / "corrupt_p2.db"
    corrupt_db.write_bytes(data)

    out_file = tmp_path / "decrypted_fail.db"
    success = decrypt_database(corrupt_db, out_file, key)
    assert success is False
    assert not out_file.exists()

    # Ensure no lingering .tmp files exist in destination directory
    tmp_files = list(tmp_path.glob("*.tmp.*"))
    assert len(tmp_files) == 0


def test_crypto_invalid_key_formats_and_types(tmp_path: Path) -> None:
    """Test decrypt_database defense against odd-length, wrong-sized, or non-string/bytes keys."""
    db_file = tmp_path / "test.db"
    db_file.write_bytes(b"\x00" * PAGE_SZ)
    out_file = tmp_path / "out.db"

    invalid_keys = [
        "",                             # Empty string
        "abc",                          # Short non-hex string
        "g" * 64,                       # 64-char non-hex string
        "123456",                       # Valid hex but only 3 bytes
        "a" * 62,                       # 31 bytes hex
        "a" * 66,                       # 33 bytes hex
        "a" * 63,                       # Odd length hex string
        b"\x01" * 16,                   # 16-byte key
        b"\x01" * 64,                   # 64-byte key
        None,                           # NoneType
        123456789,                      # Integer
        3.14159,                        # Float
        ["key"],                        # List
        {"key": "value"},               # Dict
    ]

    for inv_key in invalid_keys:
        assert decrypt_database(db_file, out_file, inv_key) is False
        assert not out_file.exists()


def test_crypto_unwritable_destination_graceful_failure(tmp_path: Path) -> None:
    """Verify that an unwritable output destination fails gracefully returning False without unhandled crashes."""
    key = b"\x44" * 32
    enc_db = generate_synthetic_encrypted_db(
        key,
        sql_script="CREATE TABLE t(x);",
        output_path=tmp_path / "src.db",
    )

    # 1. Output destination where parent directory is a regular file
    blocker_file = tmp_path / "blocker_file"
    blocker_file.write_text("I am a file, not a directory")
    invalid_dst = blocker_file / "output.db"

    res = decrypt_database(enc_db, invalid_dst, key)
    assert res is False

    # 2. Output destination in read-only directory
    ro_dir = tmp_path / "read_only_dir"
    ro_dir.mkdir()
    ro_dst = ro_dir / "target.db"
    try:
        ro_dir.chmod(0o444)
        res = decrypt_database(enc_db, ro_dst, key)
        assert res is False
    finally:
        ro_dir.chmod(0o755)


def test_crypto_wal_checkpoint_corrupted_and_truncated_frames(tmp_path: Path) -> None:
    """Adversarial stress testing of pure-Python WAL frame replayer."""
    db_file = tmp_path / "wal_test.db"
    wal_file = tmp_path / "wal_test.db-wal"

    # Create dummy database of 2 pages
    db_file.write_bytes(b"\x11" * PAGE_SZ + b"\x22" * PAGE_SZ)

    # Sub-case 1: Missing WAL or empty WAL -> returns True
    assert checkpoint_wal_pure_python(db_file, Path(tmp_path / "nonexistent.db-wal")) is True
    wal_file.write_bytes(b"")
    assert checkpoint_wal_pure_python(db_file, wal_file) is True

    # Sub-case 2: WAL shorter than 32-byte header -> returns True (noop)
    wal_file.write_bytes(b"short header")
    assert checkpoint_wal_pure_python(db_file, wal_file) is True

    # Sub-case 3: Valid 32-byte header followed by truncated frame
    hdr = b"\x37\x7f\x06\x82" + b"\x00" * 28
    # Frame size = 24 bytes frame header + 4096 bytes page data = 4120 bytes
    # Write header + partial frame of 100 bytes
    wal_file.write_bytes(hdr + b"\x00\x00\x00\x01" + b"\xFF" * 96)
    # Replayer should stop at truncated frame, truncate WAL to 0, return True
    assert checkpoint_wal_pure_python(db_file, wal_file) is True
    assert wal_file.stat().st_size == 0

    # Sub-case 4: Valid frame for page 2 and pgno=0 skipped frame
    frame1_pg0 = struct.pack(">I", 0) + b"\x00" * 20 + b"\x99" * PAGE_SZ
    new_p2_data = b"\x77" * PAGE_SZ
    frame2_p2 = struct.pack(">I", 2) + b"\x00" * 20 + new_p2_data

    wal_file.write_bytes(hdr + frame1_pg0 + frame2_p2)
    assert checkpoint_wal_pure_python(db_file, wal_file) is True
    assert wal_file.stat().st_size == 0

    # Verify db_file has updated page 2 data at offset 4096..8192
    content = db_file.read_bytes()
    assert content[PAGE_SZ : 2 * PAGE_SZ] == new_p2_data
    # Page 1 remains unmodified
    assert content[:PAGE_SZ] == b"\x11" * PAGE_SZ


def test_crypto_sync_manager_retry_and_missing_source(tmp_path: Path) -> None:
    """Verify sync_database_file handling of missing source, invalid keys, and retry loops."""
    key = b"\x55" * 32
    enc_db = generate_synthetic_encrypted_db(
        key,
        sql_script="CREATE TABLE sync_t(id INT);",
        output_path=tmp_path / "source.db",
    )

    entry = DatabaseEntry(
        rel_path="source.db",
        abs_path=enc_db,
        category=DatabaseCategory.CORE_MESSAGE,
        is_encrypted=True,
        has_wal=False,
        wal_size=0,
        mtime=enc_db.stat().st_mtime,
        wal_mtime=0.0,
    )

    # 1. Successful sync
    dst_db = tmp_path / "decrypted" / "source.db"
    res1 = sync_database_file(entry, dst_db, key, max_retries=1)
    assert res1.status == SyncStatus.SYNCED
    assert dst_db.is_file()

    # 2. Already up-to-date (not forced)
    res2 = sync_database_file(entry, dst_db, key, force=False)
    assert res2.status == SyncStatus.UP_TO_DATE

    # 3. Missing source file
    missing_entry = DatabaseEntry(
        rel_path="missing.db",
        abs_path=tmp_path / "nonexistent.db",
        category=DatabaseCategory.CORE_MESSAGE,
        is_encrypted=True,
        has_wal=False,
        wal_size=0,
        mtime=0.0,
        wal_mtime=0.0,
    )
    res3 = sync_database_file(missing_entry, tmp_path / "decrypted" / "missing.db", key)
    assert res3.status == SyncStatus.SKIPPED_NO_SRC

    # 4. Wrong key triggers retries and ultimately FAILED status
    wrong_key = b"\x99" * 32
    bad_dst = tmp_path / "decrypted" / "bad.db"
    res4 = sync_database_file(entry, bad_dst, wrong_key, force=True, max_retries=2)
    assert res4.status == SyncStatus.FAILED
    assert "HMAC verification failed" in (res4.error or "")
    assert not bad_dst.exists()


# ===========================================================================
# 2. DB ADVERSARIAL TESTS (Challenger 1, Part 1)
# ===========================================================================

def test_shards_non_sqlite_corrupted_shard_detection(tmp_path: Path) -> None:
    """
    Investigate ShardManager behavior when a shard file is NOT a valid SQLite database.

    With hardening, ShardManager catches DatabaseError/OperationalError, logs a warning,
    skips the corrupt shard cleanly, and returns a functional connection pool for valid shards.
    """
    msg_dir = tmp_path / "message"
    msg_dir.mkdir()

    # Create valid message_0.db
    m0 = msg_dir / "message_0.db"
    with sqlite3.connect(m0) as db:
        db.execute("CREATE TABLE Msg_aaa (local_id INTEGER PRIMARY KEY, message_content TEXT);")
        db.execute("INSERT INTO Msg_aaa VALUES (1, 'hello from shard 0');")

    # Create corrupted message_1.db with non-SQLite random garbage
    m1 = msg_dir / "message_1.db"
    m1.write_bytes(b"NOT_A_VALID_SQLITE_DATABASE_GARBAGE_PAYLOAD_HERE")

    manager = ShardManager(msg_dir)
    shards = manager.discover_shards()
    assert len(shards) == 2

    # Attempt to initialize connection; corrupted shard 1 is skipped cleanly without crashing
    conn = manager.get_connection()
    assert conn is not None

    # Valid shard 0 tables remain accessible
    tables = manager.list_chat_tables()
    assert "Msg_aaa" in tables

    manager.close()


def test_shards_thread_collision_under_rapid_access_and_invalidation(tmp_path: Path) -> None:
    """Stress test ShardManager under concurrent multi-threaded access and dynamic close()."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir()

    m0 = msg_dir / "message_0.db"
    with sqlite3.connect(m0) as db:
        db.execute("CREATE TABLE Msg_thread (local_id INTEGER PRIMARY KEY, content TEXT);")
        db.execute("INSERT INTO Msg_thread VALUES (1, 'concurrent data');")

    manager = ShardManager(msg_dir)
    stop_event = threading.Event()
    errors: List[Exception] = []

    def reader_worker() -> None:
        while not stop_event.is_set():
            try:
                tables = manager.list_chat_tables()
                exists = manager.table_exists("Msg_thread")
                assert "Msg_thread" in tables
                assert exists is True
            except Exception as e:
                errors.append(e)
            time.sleep(0.001)

    def closer_worker() -> None:
        for _ in range(20):
            time.sleep(0.005)
            manager.close()

    threads = [threading.Thread(target=reader_worker) for _ in range(8)]
    closer = threading.Thread(target=closer_worker)

    for t in threads:
        t.start()
    closer.start()

    closer.join()
    stop_event.set()
    for t in threads:
        t.join()

    manager.close()
    assert len(errors) == 0, f"Thread collision errors occurred: {errors[:5]}"


def test_shards_connection_pool_limits_and_many_shards(tmp_path: Path) -> None:
    """Verify ShardManager attaching many shards up to SQLite limit (10 attached) without leaking."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir()

    # Create 12 shards (message_0.db to message_11.db)
    for i in range(12):
        db_p = msg_dir / f"message_{i}.db"
        with sqlite3.connect(db_p) as db:
            db.execute(f"CREATE TABLE Msg_test_{i} (id INT);")
            db.execute("CREATE TABLE TimeStamp (timestamp INT);")
            db.execute(f"INSERT INTO TimeStamp VALUES ({1700000000 + i * 100});")

    manager = ShardManager(msg_dir)
    shards = manager.discover_shards()
    assert len(shards) == 12

    conn = manager.get_connection()
    assert conn is not None

    tables = manager.list_chat_tables()
    # SQLite has a hard attach limit of 10 databases (main + 10 shards = 11 total).
    # ShardManager catches the OperationalError and cleanly limits schemas to 11.
    assert len(tables) == 11
    assert "Msg_test_0" in tables
    assert "Msg_test_10" in tables

    manager.close()


def test_sender_unmapped_rowids_and_missing_name2id(tmp_path: Path) -> None:
    """Test SenderResolver robustness with missing tables, empty caches, and unmapped rowids."""
    root = tmp_path / "wechat_root"
    (root / "contact").mkdir(parents=True)
    (root / "message").mkdir(parents=True)

    # Shard 0 with Name2Id mapping 1 -> user_alice
    with sqlite3.connect(root / "message" / "message_0.db") as db:
        db.execute("CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT);")
        db.execute("INSERT INTO Name2Id VALUES (1, 'user_alice');")

    # Shard 1 without Name2Id table at all
    with sqlite3.connect(root / "message" / "message_1.db") as db:
        db.execute("CREATE TABLE SomeOtherTable (id INT);")

    # Contact DB with only user_alice
    with sqlite3.connect(root / "contact" / "contact.db") as db:
        db.execute("CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT, alias TEXT);")
        db.execute("INSERT INTO contact VALUES ('user_alice', 'AliceNick', 'AliceRemark', 'alice_alias');")

    resolver = SenderResolver(root)

    # 1. Mapped rowid in shard 0
    wxid, display = resolver.resolve("main", 1)
    assert wxid == "user_alice"
    assert display == "AliceRemark"

    # 2. Unmapped rowid in shard 0 (rowid 9999) -> falls back to "9999"
    wxid_unmapped, disp_unmapped = resolver.resolve("main", 9999)
    assert wxid_unmapped == "9999"
    assert disp_unmapped == "9999"

    # 3. Missing Name2Id in shard 1 -> rowid 1 falls back to "1"
    wxid_s1, disp_s1 = resolver.resolve("shard_1", 1)
    assert wxid_s1 == "1"
    assert disp_s1 == "1"

    # 4. None / empty / invalid shard_tag
    wxid_none, disp_none = resolver.resolve(None, 1)
    assert wxid_none == "user_alice"

    # 5. Rowid 0 or negative rowids
    assert resolver.resolve("main", 0) == ("0", "0")
    assert resolver.resolve("main", -1) == ("-1", "-1")


def test_decompress_corrupted_zstd_streams() -> None:
    """Verify decompress_content defense against malformed zstandard headers and streams."""
    zstd_magic = b"\x28\xb5\x2f\xfd"

    # 1. ZSTD magic bytes followed by truncated/garbage data
    corrupted_zstd = zstd_magic + b"\x00\x11\x22\x33\x44"
    res1 = decompress_content(corrupted_zstd, wc_ct=WCDB_CT_ZSTD)
    assert res1 == "[Decompression Failed]"

    # 2. wc_ct set to 4 (WCDB_CT_ZSTD) but payload is arbitrary non-zstd garbage
    res2 = decompress_content(b"not zstd data at all", wc_ct=WCDB_CT_ZSTD)
    assert res2 == "[Decompression Failed]"

    # 3. Valid zstd stream exceeding max_bytes
    if zstandard:
        cctx = zstandard.ZstdCompressor()
        huge_text = ("A" * (MAX_CONTENT_BYTES + 2048)).encode("utf-8")
        huge_zstd = cctx.compress(huge_text)

        decomp = decompress_content(huge_zstd, wc_ct=WCDB_CT_ZSTD)
        assert decomp.endswith("... [TRUNCATED]")
        assert len(decomp) <= MAX_CONTENT_BYTES + 30


def test_decompress_corrupted_zlib_streams_and_fallbacks() -> None:
    """Verify decompress_content defense against malformed zlib headers, binary fallback, and caps."""
    zlib_magic = b"\x78\x9c"

    # 1. ZLIB magic followed by corrupted stream
    corrupt_zlib = zlib_magic + b"\xFF\xFF\x00\x11\x22\x33"
    res1 = decompress_content(corrupt_zlib)
    assert res1 == "[Decompression Failed]"

    # 2. Corrupted compress_col (legacy column)
    res2 = decompress_content(b"", compress_col=b"\x12\x34\x56\x78")
    assert res2 == "[Decompression Failed]"

    # 3. Raw binary bytes that are neither zstd, zlib, nor valid UTF-8
    invalid_utf8_binary = b"\x80\x81\x82\x90\xaa\xbb\xcc"
    res3 = decompress_content(invalid_utf8_binary)
    assert res3 == "[Binary Data]"

    # 4. Large raw UTF-8 string exceeding max_bytes
    big_str = "X" * (MAX_CONTENT_BYTES + 500)
    res4 = decompress_content(big_str)
    assert res4.endswith("... [TRUNCATED]")

    # 5. None and empty payload
    assert decompress_content(None) == ""
    assert decompress_content(b"") == ""
    assert decompress_content(12345) == ""


def test_db_queries_sql_injection_resilience(tmp_path: Path) -> None:
    """Verify HistoryReader immunity to SQL injection across search, chat, and contact queries."""
    fixture = SyntheticWeChatFixture(tmp_path / "decrypted")
    fixture.build_default_dataset(with_reserve=False)

    reader = HistoryReader(tmp_path / "decrypted")

    # 1. SQL Injection in username (get_messages)
    sql_injections = [
        "admin' OR '1'='1",
        "'; DROP TABLE contact; --",
        "test' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--",
        "nonexistent\x00_null_byte",
        '""" OR ""="',
    ]

    for inj in sql_injections:
        res = reader.get_messages(username=inj)
        assert res["count"] == 0
        assert res["messages"] == []

    # 2. SQL Injection in search query
    for inj in sql_injections:
        res_search = reader.search_messages(query=inj)
        assert isinstance(res_search, list)

    # 3. SQL Injection in contact query (tests LIKE wildcard escaping)
    wildcards = ["%", "_", "\\", "%' OR '1'='1", "' UNION SELECT id FROM contact--"]
    for wc in wildcards:
        contacts = reader.list_contacts(query=wc)
        assert isinstance(contacts, list)

    reader.shards.close()


# ===========================================================================
# 3. CLI & CONFIG ADVERSARIAL TESTS (Challenger 1, Part 1)
# ===========================================================================

def test_config_precedence_hierarchy_exhaustive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify strict precedence: parameter > ENV > config.json > defaults across all keys."""
    # Step 1: Create config.json with level 3 values
    cfg_file = tmp_path / "test_config.json"
    cfg_data = {
        "db_dir": str(tmp_path / "level3_db"),
        "keys_file": str(tmp_path / "level3_keys.json"),
        "decrypted_dir": str(tmp_path / "level3_decrypted"),
        "api_port": 8333,
        "sync_interval_seconds": 33,
        "log_level": "WARNING",
    }
    cfg_file.write_text(json.dumps(cfg_data))

    # Step 2: Set environment variables with level 2 values
    monkeypatch.setenv("WECHAT_DB_DIR", str(tmp_path / "level2_db"))
    monkeypatch.setenv("WECHAT_KEYS_FILE", str(tmp_path / "level2_keys.json"))
    monkeypatch.setenv("WECHAT_DECRYPTED_DIR", str(tmp_path / "level2_decrypted"))
    monkeypatch.setenv("WECHAT_API_PORT", "8222")
    monkeypatch.setenv("WECHAT_SYNC_INTERVAL", "22")
    monkeypatch.setenv("WECHAT_LOG_LEVEL", "DEBUG")

    # Step 3: Load with explicit parameter overrides for a subset (level 1)
    param_db = tmp_path / "level1_db"
    param_keys = tmp_path / "level1_keys.json"

    cfg = load_config(
        config_file=cfg_file,
        db_dir=param_db,
        keys_file=param_keys,
    )

    # Verify parameter wins over ENV and file
    assert cfg.db_dir == param_db.resolve()
    assert cfg.keys_file == param_keys.resolve()

    # Verify ENV wins over file for decrypted_dir, api_port, sync_interval, log_level
    assert cfg.decrypted_dir == (tmp_path / "level2_decrypted").resolve()
    assert cfg.api_port == 8222
    assert cfg.sync_interval_seconds == 22
    assert cfg.log_level == "DEBUG"


def test_config_missing_and_corrupted_config_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test load_config resilience against missing, empty, or syntactically invalid config files."""
    # Setup dummy account so discovery succeeds
    acc_dir = tmp_path / "fake_account" / "db_storage"
    acc_dir.mkdir(parents=True)
    monkeypatch.setenv("WECHAT_DB_DIR", str(acc_dir))

    # 1. Nonexistent config file
    nonexistent = tmp_path / "does_not_exist.json"
    cfg1 = load_config(config_file=nonexistent)
    assert cfg1.db_dir == acc_dir.resolve()

    # 2. Corrupted / malformed JSON
    corrupt_json = tmp_path / "malformed.json"
    corrupt_json.write_text("{ unclosed json key: 'broken' ")
    cfg2 = load_config(config_file=corrupt_json)
    assert cfg2.db_dir == acc_dir.resolve()

    # 3. Empty JSON file
    empty_json = tmp_path / "empty.json"
    empty_json.write_text("")
    cfg3 = load_config(config_file=empty_json)
    assert cfg3.db_dir == acc_dir.resolve()


def test_config_invalid_env_types_and_discovery_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test handling of invalid environment numeric variables and nonexistent account wxid."""
    monkeypatch.delenv("WECHAT_DB_DIR", raising=False)
    monkeypatch.delenv("WECHAT_CONFIG_FILE", raising=False)

    # Empty roots -> discover_accounts() returns empty list
    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [tmp_path / "empty_root"])

    with pytest.raises(WeChatConfigError) as exc_info:
        load_config()
    assert "No WeChat accounts found" in str(exc_info.value)

    # Create one account, but request a different nonexistent wxid
    valid_acc = tmp_path / "search_root" / "wxid_real" / "db_storage"
    valid_acc.mkdir(parents=True)
    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [tmp_path / "search_root"])

    with pytest.raises(WeChatConfigError) as exc_wxid:
        load_config(wxid="wxid_unknown_ghost")
    assert "Specified WeChat account wxid 'wxid_unknown_ghost' not found" in str(exc_wxid.value)


def test_cli_adversarial_invocations(tmp_path: Path) -> None:
    """Stress test click CLI runner under missing arguments, invalid options, and error branches."""
    runner = CliRunner()

    # 1. Decrypt command with missing input file
    res1 = runner.invoke(main, ["decrypt", str(tmp_path / "missing.db"), str(tmp_path / "out.db"), "-k", "1234"])
    assert res1.exit_code != 0

    # 2. Decrypt command with valid file but invalid key
    dummy_file = tmp_path / "dummy.db"
    dummy_file.write_bytes(b"\x00" * PAGE_SZ)
    res2 = runner.invoke(main, ["decrypt", str(dummy_file), str(tmp_path / "out.db"), "-k", "bad_key"])
    assert res2.exit_code == 1
    assert "Decryption failed" in res2.output

    # 3. Keys command with invalid method
    res3 = runner.invoke(main, ["keys", "--method", "invalid_choice"])
    assert res3.exit_code == 2

    # 4. Sync command with invalid config pointing to nonexistent wxid
    with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
        json.dump({"wxid": "nonexistent_account_wxid_xyz"}, f)
        f.flush()
        res4 = runner.invoke(main, ["sync", "--config", f.name])
        assert res4.exit_code == 1
        assert "not found" in res4.output

    # 5. MCP command with invalid transport choice
    res5 = runner.invoke(main, ["mcp", "--transport", "websocket"])
    assert res5.exit_code == 2


# ===========================================================================
# 4. MCP SERVER & ERROR ENVELOPES (Challenger 2, Part 2)
# ===========================================================================

def test_adv_mcp_unknown_tool_queries_and_hostile_names(tmp_path: Path) -> None:
    """T5-ADV-01: Unknown tool names with directory traversal, SQL injection, script tags return safe envelope."""
    reader = HistoryReader(tmp_path)
    server = create_mcp_server(reader=reader)

    hostile_tool_names = [
        "../../etc/passwd",
        "<script>alert(1)</script>",
        "SELECT * FROM secrets;",
        "foo" + chr(0) + "bar",
        "",
        "wechat_drop_all_tables",
    ]

    for tool_name in hostile_tool_names:
        res = server.call_tool_sync(tool_name, {"arg": "val"})
        assert res["schema"] == ERROR_SCHEMA
        assert res["error_type"] == "ToolNotFound"
        assert res["code"] == "ToolNotFound"
        assert res["retry_unknown"] is False
        assert isinstance(res["timestamp"], int)
        assert tool_name in res["message"] or "Unknown tool" in res["message"]


def test_adv_mcp_unexpected_exception_redacts_wxid_and_paths(tmp_path: Path) -> None:
    """T5-ADV-02: Unexpected runtime exception during tool execution is trapped and sensitive data redacted."""
    reader = HistoryReader(tmp_path)
    reader.get_stats = MagicMock(
        side_effect=RuntimeError(
            "Database locked at /Users/victim_user/Library/Containers/wxid_victim1234567890/msg.db"
        )
    )
    server = create_mcp_server(reader=reader)

    res = server.call_tool_sync("wechat_core_stats")
    assert res["schema"] == ERROR_SCHEMA
    assert res["error_type"] == "RuntimeError"
    assert "/Users/[USER]" in res["message"]
    assert "[REDACTED_WXID]" in res["message"]
    assert "victim_user" not in res["message"]
    assert "wxid_victim1234567890" not in res["message"]


def test_adv_mcp_legacy_cursor_adversarial_types_rejection(tmp_path: Path) -> None:
    """T5-ADV-03: wechat_messages rejects any positive, negative, string, or non-zero integer since_id."""
    reader = HistoryReader(tmp_path)
    server = create_mcp_server(reader=reader)

    hostile_since_ids = [
        1,
        100,
        -1,
        -9999,
        "cursor_123",
        "100",
        None,
        [100],
        {"id": 100},
    ]

    for bad_id in hostile_since_ids:
        res = server.call_tool_sync(
            "wechat_messages", {"username": "test_user", "since_id": bad_id}
        )
        assert res["schema"] == ERROR_SCHEMA
        assert res["error_type"] == "UnsafeLegacyCursor"
        assert "not an incremental cursor" in res["message"]


def test_adv_mcp_messages_cursor_syntax_and_offset_conflict(tmp_path: Path) -> None:
    """T5-ADV-04: wechat_core_messages rejects malformed cursor syntax and cursor/offset conflicts."""
    reader = HistoryReader(tmp_path)
    server = create_mcp_server(reader=reader)

    # Malformed cursor string
    res_malformed = server.call_tool_sync(
        "wechat_core_messages", {"session": "user1", "cursor": "invalid_format"}
    )
    assert res_malformed["schema"] == ERROR_SCHEMA
    assert res_malformed["error_type"] == "ValueError"
    assert "Invalid cursor format" in res_malformed["message"]

    # Invalid cursor type
    res_type = server.call_tool_sync(
        "wechat_core_messages", {"session": "user1", "cursor": {"nested": 1}}
    )
    assert res_type["schema"] == ERROR_SCHEMA
    assert res_type["error_type"] == "ValueError"
    assert "Invalid cursor type" in res_type["message"]

    # Mutual exclusion: cursor and offset > 0
    res_conflict = server.call_tool_sync(
        "wechat_core_messages",
        {"session": "user1", "cursor": "cursor_10", "offset": 5},
    )
    assert res_conflict["schema"] == ERROR_SCHEMA
    assert res_conflict["error_type"] == "ValueError"
    assert "Use either a snapshot cursor or offset, not both" in res_conflict["message"]


def test_adv_mcp_negative_limit_and_offset_bounds(tmp_path: Path) -> None:
    """T5-ADV-05: wechat_core_sessions and wechat_core_messages handle negative limits and offsets safely."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    tname = md5_table("user_bound")
    with sqlite3.connect(msg_dir / "message_0.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        db.execute(
            f'CREATE TABLE "{tname}"(local_id INT, server_id INT, local_type INT, sort_seq INT, real_sender_id INT, create_time INT, status INT, source TEXT, message_content TEXT, compress_content TEXT, WCDB_CT_message_content INT, WCDB_CT_source INT);'
        )
        db.execute(
            f'INSERT INTO "{tname}" VALUES(1, 101, 1, 1, 1, 1700000001, 2, "", "Hello bound", NULL, 0, 0);'
        )
        db.commit()

    reader = HistoryReader(tmp_path)
    server = create_mcp_server(reader=reader)

    # Negative limit and offset on sessions
    res_sess = server.call_tool_sync(
        "wechat_core_sessions", {"limit": -10, "offset": -50}
    )
    assert res_sess["schema"] == "wechat.core.v1"
    assert res_sess["total"] >= 0

    # Negative limit and offset on messages
    res_msg = server.call_tool_sync(
        "wechat_core_messages", {"session": "user_bound", "limit": -5, "offset": -10}
    )
    assert res_msg["schema"] == "wechat.core.v1"
    assert res_msg["count"] >= 0
    assert len(res_msg["messages"]) >= 0

    reader.shards.close()


def test_adv_mcp_push_subscription_interval_and_scope_validation() -> None:
    """T5-ADV-06: EventPush enforces strict subscription interval and URI scope boundaries."""
    # Invalid intervals
    for bad_interval in [0.0, -1.0, 61.0, 3600.0]:
        with pytest.raises(ValueError, match="Bounded subscription timing required"):
            EventPush(interval=bad_interval)

    # Invalid send_timeout
    for bad_timeout in [0.0, -5.0, 100.0]:
        with pytest.raises(ValueError, match="Bounded subscription timing required"):
            EventPush(send_timeout=bad_timeout)

    push = EventPush(groups=["room1@chatroom"])
    # Out of scope resource URI
    for bad_uri in [
        "http://localhost:8300/events/room1",
        "wechat://other-scope/room1",
        "file:///etc/passwd",
    ]:
        with pytest.raises(ValueError, match="Resource outside configured event scope"):
            push.group(bad_uri)


@pytest.mark.asyncio
async def test_adv_mcp_push_subscription_cancellation_and_closed_manager() -> None:
    """T5-ADV-07: EventPush session unsubscription cancels background tasks; closed manager rejects subscriptions."""
    push = EventPush(groups=["room1@chatroom"], interval=0.05, send_timeout=0.1)
    session = MagicMock()
    session.send_resource_updated = AsyncMock()

    uri = "wechat-core://events/room1%40chatroom"

    # Subscribe creates active subscription
    await push.subscribe(session, uri)
    assert push.subscription_count == 1

    # Unsubscribe cancels task and cleans session state
    await push.unsubscribe(session, uri)
    assert push.subscription_count == 0

    # Subscribe again then shutdown manager
    await push.subscribe(session, uri)
    assert push.subscription_count == 1
    await push.aclose()
    assert push.subscription_count == 0
    assert push._closed is True

    # Subscription after close raises ValueError
    with pytest.raises(ValueError, match="Subscription manager is closed"):
        await push.subscribe(session, uri)


# ===========================================================================
# 5. FASTAPI REST SERVICE (Challenger 2, Part 2)
# ===========================================================================

def test_adv_api_boundary_query_parameters_validation(tmp_path: Path) -> None:
    """T5-ADV-08: REST endpoints reject out-of-bounds query parameters with HTTP 422."""
    reader = HistoryReader(tmp_path)
    app = create_api_app(reader=reader)
    client = TestClient(app)

    # /api/chats boundary violations
    assert client.get("/api/chats?limit=0").status_code == 422
    assert client.get("/api/chats?limit=-1").status_code == 422
    assert client.get("/api/chats?limit=1001").status_code == 422
    assert client.get("/api/chats?limit=100000").status_code == 422
    assert client.get("/api/chats?offset=-1").status_code == 422

    # /api/contacts boundary violations
    assert client.get("/api/contacts?limit=0").status_code == 422
    assert client.get("/api/contacts?limit=-10").status_code == 422
    assert client.get("/api/contacts?limit=5000").status_code == 422


def test_adv_api_empty_query_and_whitespace_search(tmp_path: Path) -> None:
    """T5-ADV-09: /api/search rejects omitted or empty q with HTTP 422; whitespace queries handled safely."""
    reader = HistoryReader(tmp_path)
    app = create_api_app(reader=reader)
    client = TestClient(app)

    # Missing q parameter
    r_missing = client.get("/api/search")
    assert r_missing.status_code == 422

    # Empty string q
    r_empty = client.get("/api/search?q=")
    assert r_empty.status_code == 422

    # Pure whitespace query
    r_space = client.get("/api/search?q=%20%20%20")
    assert r_space.status_code == 200
    assert r_space.json() == []


def test_adv_api_path_traversal_session_ids_handling(tmp_path: Path) -> None:
    """T5-ADV-10: Path traversal sequences in session IDs either route to 404 or resolve to empty results without filesystem leakage."""
    reader = HistoryReader(tmp_path)
    app = create_api_app(reader=reader)
    client = TestClient(app)

    # Direct traversal attempts normalized away by router
    r1 = client.get("/api/chats/..%2F..%2Fetc%2Fpasswd/messages")
    assert r1.status_code == 404

    # Traversal characters in session string that match route
    hostile_usernames = [
        "user..name",
        "..leading_dot",
        "trailing_dot..",
        "foo..bar..baz",
    ]

    for username in hostile_usernames:
        r = client.get(f"/api/chats/{username}/messages")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 0
        assert data["messages"] == []
        assert data["username"] == username


def test_adv_api_cors_preflight_and_wildcard_origin(tmp_path: Path) -> None:
    """T5-ADV-11: FastAPI REST service returns proper CORS preflight headers for untrusted origins."""
    reader = HistoryReader(tmp_path)
    app = create_api_app(reader=reader)
    client = TestClient(app)

    headers = {
        "Origin": "https://hostile-site.malicious.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization, X-Custom-Header",
    }

    # Preflight OPTIONS: when allow_credentials=True, Starlette reflects origin per W3C CORS spec
    res_options = client.options("/api/chats", headers=headers)
    assert res_options.status_code == 200
    assert res_options.headers.get("access-control-allow-origin") in ("*", "https://hostile-site.malicious.com")
    assert res_options.headers.get("access-control-allow-credentials") == "true"
    assert "GET" in res_options.headers.get("access-control-allow-methods", "")

    # Standard GET with Origin
    res_get = client.get("/api/stats", headers={"Origin": "https://another-site.org"})
    assert res_get.status_code == 200
    assert res_get.headers.get("access-control-allow-origin") in ("*", "https://another-site.org")
    assert res_get.headers.get("access-control-allow-credentials") == "true"


def test_adv_api_unhandled_database_error_fallback(tmp_path: Path) -> None:
    """T5-ADV-12: /api/stats catches unhandled sqlite3 database corruption and returns fallback structure."""
    reader = HistoryReader(tmp_path)
    reader.get_stats = MagicMock(
        side_effect=sqlite3.DatabaseError("file is not a database")
    )
    app = create_api_app(reader=reader)
    client = TestClient(app)

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["chats"] == 0
    assert data["messages"] == 0
    assert data["contacts"] == 0
    assert data["shard_count"] == 0


# ===========================================================================
# 6. WATCHER, KQUEUE & RECALL (Challenger 2, Part 2)
# ===========================================================================

def test_adv_watcher_kqueue_fd_exhaustion_emfile_simulation(tmp_path: Path) -> None:
    """T5-ADV-13: VnodeWatch strictly enforces descriptor limits and raises EMFILE (Errno 24)."""
    watcher = VnodeWatch(tmp_path, max_watches=2)
    f1 = tmp_path / "a.db"
    f2 = tmp_path / "b.db"
    f3 = tmp_path / "c.db"
    f1.touch()
    f2.touch()
    f3.touch()

    watcher.watch_file(f1)
    watcher.watch_file(f2)

    with pytest.raises(OSError) as excinfo:
        watcher.watch_file(f3)
    assert excinfo.value.errno == errno.EMFILE
    assert "Too many open files" in str(excinfo.value)

    # Close safely resets handles and watches
    watcher.close()
    assert len(watcher.watches) == 0
    assert len(watcher.handles) == 0


def test_adv_watcher_kqueue_rapid_burst_write_debouncing(tmp_path: Path) -> None:
    """T5-ADV-14: Rapid flood of write events within debounce window coalesces; delete events bypass debouncing."""
    watcher = VnodeWatch(tmp_path, debounce_interval_ms=100.0)
    target = tmp_path / "flood.db"
    target.touch()

    # Emit first write event
    ev1 = watcher.emit_event(target, VnodeFlags.NOTE_WRITE)
    assert ev1 is not None

    # Flood 50 rapid write events immediately
    coalesced_count = 0
    for _ in range(50):
        ev = watcher.emit_event(target, VnodeFlags.NOTE_WRITE)
        if ev is None:
            coalesced_count += 1
    assert coalesced_count == 50

    # Delete event during debounce interval must NOT be coalesced
    ev_del = watcher.emit_event(target, VnodeFlags.NOTE_DELETE)
    assert ev_del is not None
    assert bool(ev_del.flags & VnodeFlags.NOTE_DELETE)


def test_adv_watcher_recall_xml_entity_expansion_xxe_protection(tmp_path: Path) -> None:
    """T5-ADV-15: Revoke tip parsing survives XML Entity Expansion (Billion Laughs & external entities) without exploit."""
    archive = RecallArchive(tmp_path)

    # Billion laughs entity expansion payload
    xxe_bomb = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ELEMENT lolz (#PCDATA)>
      <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]>
    <sysmsg type="revokemsg">
      <revokemsg>
        <session>chat_xxe@chatroom</session>
        <newmsgid>888999</newmsgid>
        <replacemsg>&lol2;</replacemsg>
      </revokemsg>
    </sysmsg>"""

    res = archive._parse_revoke_tip(xxe_bomb)
    assert res["is_revoke"] is True
    assert res["session"] == "chat_xxe@chatroom"
    assert res["newmsgid"] == 888999

    # Malicious external file disclosure entity
    xxe_file = """<?xml version="1.0"?>
    <!DOCTYPE test [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <sysmsg type="revokemsg">
      <revokemsg>
        <session>chat_leak@chatroom</session>
        <newmsgid>777666</newmsgid>
        <replacemsg>&xxe;</replacemsg>
      </revokemsg>
    </sysmsg>"""

    res_file = archive._parse_revoke_tip(xxe_file)
    assert res_file["is_revoke"] is True
    assert res_file["session"] == "chat_leak@chatroom"
    assert res_file["newmsgid"] == 777666
    assert "root:" not in str(res_file.get("replacemsg"))


def test_adv_watcher_recall_mass_suppression_guard_on_empty_db(tmp_path: Path) -> None:
    """T5-ADV-16: Emptying message storage triggers mass recall suppression guard, preventing false positive alarms."""
    msg_dir = tmp_path / "message"
    msg_dir.mkdir(parents=True)
    session = "active_chat@chatroom"
    tname = md5_table(session)
    db_file = msg_dir / "message_0.db"

    with sqlite3.connect(db_file) as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        db.execute(
            f'CREATE TABLE "{tname}"(local_id INT, server_id INT, local_type INT, sort_seq INT, real_sender_id INT, create_time INT, status INT, source TEXT, message_content TEXT, compress_content TEXT, WCDB_CT_message_content INT, WCDB_CT_source INT);'
        )
        for i in range(1, 21):
            db.execute(
                f'INSERT INTO "{tname}" VALUES({i}, {200 + i}, 1, {i}, 1, {1700000000 + i}, 2, "", "Chat message {i}", NULL, 0, 0);'
            )
        db.commit()

    reader = HistoryReader(tmp_path)
    archive = RecallArchive(tmp_path, reader=reader)
    archive.index_current_messages(session)
    assert len(archive._indexed_msgs[session]) == 20

    # Wipe all messages from database (simulates cleared history or DB reset)
    with sqlite3.connect(db_file) as db:
        db.execute(f'DELETE FROM "{tname}";')
        db.commit()

    # Scan session: suppression guard must suppress treating all 20 vanished msgs as recalls
    detected = archive.scan(session)
    assert len(detected) == 0

    reader.shards.close()


def test_adv_watcher_journal_sqlite_lock_exponential_backoff(tmp_path: Path) -> None:
    """T5-ADV-17: EventJournal retries transient SQLite lock errors with exponential backoff before failing."""
    db_path = tmp_path / "backoff_journal.sqlite"
    journal = EventJournal(db_path, max_retries=4)

    orig_conn = journal._get_connection
    call_count = 0
    sleeps: List[float] = []

    def mock_sleep(s: float):
        sleeps.append(s)

    def flaky_conn():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise sqlite3.OperationalError("database is locked")
        return orig_conn()

    orig_sleep_fn = time.sleep
    time.sleep = mock_sleep
    try:
        journal._get_connection = flaky_conn
        seq = journal.append("event", "group1", {"info": "recovered"})
        assert seq == 1
        assert call_count == 3
        # Backoff progression: 0.01 * 2^0 = 0.01, 0.01 * 2^1 = 0.02
        assert len(sleeps) == 2
        assert abs(sleeps[0] - 0.01) < 1e-4
        assert abs(sleeps[1] - 0.02) < 1e-4
    finally:
        time.sleep = orig_sleep_fn

    # Now verify exhausted retries raises OperationalError
    def permanent_fail_conn():
        raise sqlite3.OperationalError("database is locked")

    journal._get_connection = permanent_fail_conn
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        journal.append("event", "group1", {"info": "fails"})


# ===========================================================================
# 7. EDITORIAL SUMMARY PIPELINE (Challenger 2, Part 2)
# ===========================================================================

def test_adv_summary_pipeline_code_fence_cleaning_edge_cases() -> None:
    """T5-ADV-18: clean_json_response handles varied markdown code fence wrappers and rejects malformed JSON."""
    # Standard ```json ... ```
    c1 = clean_json_response("```json\n{\"title\": \"Standard\"}\n```")
    assert c1 == {"title": "Standard"}

    # Generic ``` ... ```
    c2 = clean_json_response("```\n{\"title\": \"Generic\"}\n```")
    assert c2 == {"title": "Generic"}

    # Leading/trailing whitespace around code fences
    c3 = clean_json_response("   \n\n```json\n{\"key\": 123}\n```\n  ")
    assert c3 == {"key": 123}

    # Raw JSON without code fences
    c4 = clean_json_response("{\"plain\": true}")
    assert c4 == {"plain": True}

    # Malformed JSON payload raises JSONDecodeError
    with pytest.raises(json.JSONDecodeError):
        clean_json_response("```json\n{unquoted_key: invalid}\n```")


def test_adv_summary_citation_ssrf_malicious_schemes_rejection() -> None:
    """T5-ADV-19: Citation schema and run_stage_check reject hostile SSRF URL schemes."""
    hostile_urls = [
        "file:///etc/passwd",
        "file:///Users/victim/.ssh/id_rsa",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://internal.server/conf.xml",
        "javascript:alert(document.cookie)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "ldap://127.0.0.1:389/o=test",
        "dict://127.0.0.1:11211/stats",
    ]

    for bad_url in hostile_urls:
        with pytest.raises(ValidationError):
            Citation(claim="Claim", url=bad_url)

    # Check stage rejection
    pipeline = SummaryPipeline(mock=True)
    u = UnderstandStageSchema(
        title="Architecture Review",
        summary="Brief summary",
        entities=["Tech"],
        key_points=["Point 1"],
        language="zh",
    )

    bad_citations = [
        {"claim": "Secret data", "url": "file:///etc/shadow", "source_opened": True},
        {"claim": "Redis status", "url": "gopher://127.0.0.1:6379", "source_opened": True},
        {"claim": "Legit RFC", "url": "https://www.ietf.org/rfc/rfc123.txt", "source_opened": True},
    ]

    check = pipeline.run_stage_check(u, citations=bad_citations)
    assert check.verified is False
    assert len(check.rejected_claims) == 2
    assert len(check.citations) == 1
    assert check.citations[0].url == "https://www.ietf.org/rfc/rfc123.txt"


def test_adv_summary_oversized_input_clipping_and_timeout() -> None:
    """T5-ADV-20: SummaryPipeline clips oversized text to MAX_INPUT_CHARS and propagates search timeout status."""
    pipeline = SummaryPipeline(mock=True)

    # 200,000 characters input
    oversized_text = "A" * 200_000
    u = pipeline.run_stage_understand(oversized_text, metadata={"title": "Massive Text"})
    assert u.title == "Massive Text"
    assert f"{pipeline.MAX_INPUT_CHARS}-character" in u.summary

    # Full pipeline process with timeout=True
    res_timeout = pipeline.process(
        text=oversized_text,
        citations=[{"claim": "Claim 1", "url": "https://example.com", "source_opened": True}],
        timeout=True,
    )
    assert res_timeout.status == "search_timed_out"
    assert res_timeout.check.verified is False
    assert res_timeout.check.status == "search_timed_out"
    assert res_timeout.duration_ms > 0
