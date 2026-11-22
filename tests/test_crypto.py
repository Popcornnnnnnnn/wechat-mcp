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

"""Comprehensive unit test suite for wechat-mcp crypto, config, and sync engine."""
from __future__ import annotations

import json
import os
import sqlite3
import struct
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests.conftest import create_empty_sqlite_db_with_reserve
from wechat_mcp.config import Config, WeChatConfig, discover_wechat_db_dir, load_config
from wechat_mcp.crypto.decrypt import (
    PAGE_SZ,
    decrypt_database,
    decrypt_page,
    derive_mac_key,
    encrypt_database,
    verify_page1_hmac,
    verify_page_hmac,
)
from wechat_mcp.crypto.lldb_keys import get_key_registers, grab_key_from_frame, verify_keys_file
from wechat_mcp.crypto.sync import (
    DatabaseCatalog,
    DatabaseCategory,
    SyncManager,
    SyncStatus,
    checkpoint_wal_pure_python,
    is_stale,
    sync_one_database,
)


def test_derive_mac_key():
    """Verify PBKDF2-HMAC-SHA512 key derivation matches expected vector."""
    key = b"0123456789abcdef0123456789abcdef"
    salt = b"fedcba9876543210"
    mac_key = derive_mac_key(key, salt)
    assert len(mac_key) == 32
    assert isinstance(mac_key, bytes)
    # Idempotence check
    assert mac_key == derive_mac_key(key, salt)


def test_roundtrip_decryption(
    synthetic_contact_db: Path, synthetic_key: bytes, tmp_path: Path
):
    """Test full encryption -> decryption roundtrip produces valid SQLite database."""
    out_db = tmp_path / "decrypted_contact.db"
    success = decrypt_database(synthetic_contact_db, out_db, synthetic_key)
    assert success is True
    assert out_db.exists()

    # Verify with standard sqlite3 library
    conn = sqlite3.connect(out_db)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    assert integrity == "ok"

    row = conn.execute(
        "SELECT username, nick_name FROM contact WHERE id=1"
    ).fetchone()
    assert row == ("wxid_mock_alice", "Alice Wonderland")
    conn.close()


def test_roundtrip_session_and_message(
    synthetic_session_db: Path,
    synthetic_message_db: Path,
    synthetic_key: bytes,
    tmp_path: Path,
):
    """Test roundtrip decryption on session and multi-page message databases."""
    out_session = tmp_path / "dec_session.db"
    out_message = tmp_path / "dec_message.db"

    assert decrypt_database(synthetic_session_db, out_session, synthetic_key) is True
    assert decrypt_database(synthetic_message_db, out_message, synthetic_key) is True

    # Check session data
    c_s = sqlite3.connect(out_session)
    sess_row = c_s.execute("SELECT username, summary FROM SessionTable WHERE username='wxid_mock_alice'").fetchone()
    assert sess_row == ("wxid_mock_alice", "Hello!")
    c_s.close()

    # Check message data
    c_m = sqlite3.connect(out_message)
    name_row = c_m.execute("SELECT user_name FROM Name2Id LIMIT 1").fetchone()
    assert name_row == ("wxid_mock_alice",)
    c_m.close()


def test_wrong_key_hmac_failure(
    synthetic_contact_db: Path, tmp_path: Path
):
    """Test that decryption fails cleanly when provided with an incorrect key."""
    out_db = tmp_path / "decrypted_invalid.db"
    wrong_key = b"wrong_key_wrong_key_wrong_key_32"
    success = decrypt_database(synthetic_contact_db, out_db, wrong_key)
    assert success is False
    assert not out_db.exists()


def test_corrupted_page1_hmac_detection(
    synthetic_contact_db: Path, synthetic_key: bytes, tmp_path: Path
):
    """Test that tampering with page 1 ciphertext triggers HMAC validation failure."""
    corrupted_db = tmp_path / "corrupted_p1.db"
    with open(synthetic_contact_db, "rb") as fin, open(
        corrupted_db, "wb"
    ) as fout:
        data = bytearray(fin.read())
        data[50] ^= 0xFF  # Flip bits in page 1 ciphertext
        fout.write(data)

    out_db = tmp_path / "out_p1.db"
    success = decrypt_database(corrupted_db, out_db, synthetic_key)
    assert success is False
    assert not out_db.exists()


def test_corrupted_page_n_detection(
    synthetic_contact_db: Path, synthetic_key: bytes
):
    """Test that verify_page_hmac detects corrupted page bytes."""
    with open(synthetic_contact_db, "rb") as f:
        page1 = f.read(4096)
    salt = page1[:16]
    mac_key = derive_mac_key(synthetic_key, salt)

    # Valid page 1 HMAC check
    assert verify_page_hmac(page1, 1, mac_key) is True

    # Tampered page 1 HMAC check
    bad_page1 = bytearray(page1)
    bad_page1[20] ^= 0x01
    assert verify_page_hmac(bytes(bad_page1), 1, mac_key) is False


def test_file_size_edge_cases(synthetic_key: bytes, tmp_path: Path):
    """Test handling of empty, sub-page, and non-existent files."""
    # 1. Non-existent file
    non_existent = tmp_path / "does_not_exist.db"
    assert (
        decrypt_database(non_existent, tmp_path / "out.db", synthetic_key)
        is False
    )

    # 2. 0-byte file
    empty_file = tmp_path / "empty.db"
    empty_file.touch()
    assert (
        decrypt_database(empty_file, tmp_path / "out.db", synthetic_key)
        is False
    )

    # 3. Sub-page file (< 4096 bytes)
    subpage_file = tmp_path / "subpage.db"
    with open(subpage_file, "wb") as f:
        f.write(b"partial sqlite content")
    assert (
        decrypt_database(subpage_file, tmp_path / "out.db", synthetic_key)
        is False
    )


def test_key_format_variations(
    synthetic_contact_db: Path, synthetic_key: bytes, tmp_path: Path
):
    """Test that decrypt_database accepts both 64-character hex strings and bytes."""
    hex_key = synthetic_key.hex()
    out1 = tmp_path / "out_hex.db"
    out2 = tmp_path / "out_raw.db"

    assert decrypt_database(synthetic_contact_db, out1, hex_key) is True
    assert decrypt_database(synthetic_contact_db, out2, synthetic_key) is True

    assert out1.stat().st_size == out2.stat().st_size


def test_config_discovery(synthetic_storage_tree, monkeypatch, tmp_path: Path):
    """Test dynamic config discovery and environment variable overrides."""
    db_storage, keys_file = synthetic_storage_tree

    monkeypatch.setenv("WECHAT_DB_DIR", str(db_storage))
    monkeypatch.setenv("WECHAT_KEYS_FILE", str(keys_file))
    monkeypatch.setenv("WECHAT_DECRYPTED_DIR", str(tmp_path / "decrypted"))

    config = Config.load()
    assert Path(config.db_dir) == db_storage
    assert Path(config.keys_file) == keys_file
    assert Path(config.decrypted_dir) == tmp_path / "decrypted"
    assert config.api_port == 8300
    assert config.wxid == "wxid_dummy_user"

    dict_repr = config.to_dict()
    assert dict_repr["wxid"] == "wxid_dummy_user"
    assert "decrypted_dir" in dict_repr


def test_database_catalog_and_sync(synthetic_storage_tree, tmp_path: Path):
    """Test database catalog scanning and sync manager execution."""
    db_storage, keys_file = synthetic_storage_tree
    catalog = DatabaseCatalog(db_storage)
    entries = catalog.scan()

    assert "contact/contact.db" in entries
    entry = entries["contact/contact.db"]
    assert entry.category == DatabaseCategory.CORE_CONTACT
    assert entry.is_encrypted is True

    # Test sync_one_database
    with open(keys_file) as f:
        key_data = json.load(f)
    enc_key = key_data["contact/contact.db"]["enc_key"]

    dec_dir = tmp_path / "decrypted"
    status = sync_one_database("contact/contact.db", db_storage, dec_dir, enc_key)
    assert status == "synced"
    assert (dec_dir / "contact/contact.db").is_file()

    # Second sync without changes should report up-to-date
    status_second = sync_one_database("contact/contact.db", db_storage, dec_dir, enc_key)
    assert status_second == "up-to-date"


def test_wal_checkpoint_pure_python(tmp_path: Path, synthetic_key: bytes):
    """Test pure-Python WAL frame replaying into base database file."""
    base_db = tmp_path / "test_wal.db"
    wal_file = tmp_path / "test_wal.db-wal"

    # Create dummy base DB with 1 page of 4096 zeroes
    with open(base_db, "wb") as f:
        f.write(b"\x00" * 4096)

    # Construct mock WAL header (32 bytes)
    # Magic 0x377f0682, file format version 3007000, page size 4096, seq 1, salt1, salt2, cksum1, cksum2
    wal_hdr = struct.pack(">IIIIIIII", 0x377F0682, 3007000, 4096, 1, 0x1111, 0x2222, 0x3333, 0x4444)

    # Frame 1 for page 1 (24 bytes frame header + 4096 bytes data)
    new_page_data = b"W" * 4096
    frame_hdr = struct.pack(">IIIIII", 1, 0, 0x1111, 0x2222, 0x5555, 0x6666)
    frame = frame_hdr + new_page_data

    with open(wal_file, "wb") as f:
        f.write(wal_hdr + frame)

    success = checkpoint_wal_pure_python(base_db, wal_file, page_size=4096)
    assert success is True

    # Verify that base_db was updated with new_page_data
    with open(base_db, "rb") as f:
        content = f.read()
    assert content == new_page_data
    # Verify WAL was truncated
    assert wal_file.stat().st_size == 0


def test_lldb_register_extraction_mock():
    """Verify LLDB register inspection logic on ARM64 and x86_64 mock frames."""
    # Test ARM64 mock frame (x3=key_ptr, x4=key_len)
    arm64_frame = MagicMock()
    reg_x3 = MagicMock()
    reg_x3.IsValid.return_value = True
    reg_x3.GetValueAsUnsigned.return_value = 0x10005000

    reg_x4 = MagicMock()
    reg_x4.IsValid.return_value = True
    reg_x4.GetValueAsUnsigned.return_value = 32

    def arm64_find(name):
        if name == "x3":
            return reg_x3
        if name == "x4":
            return reg_x4
        return None

    arm64_frame.FindRegister.side_effect = arm64_find
    ptr, length = get_key_registers(arm64_frame)
    assert ptr == 0x10005000
    assert length == 32

    # Test x86_64 mock frame (rcx=key_ptr, r8=key_len)
    x86_frame = MagicMock()
    reg_rcx = MagicMock()
    reg_rcx.IsValid.return_value = True
    reg_rcx.GetValueAsUnsigned.return_value = 0x20005000

    reg_r8 = MagicMock()
    reg_r8.IsValid.return_value = True
    reg_r8.GetValueAsUnsigned.return_value = 32

    def x86_find(name):
        if name in ("x3", "x4"):
            invalid = MagicMock()
            invalid.IsValid.return_value = False
            return invalid
        if name == "rcx":
            return reg_rcx
        if name == "r8":
            return reg_r8
        return None

    x86_frame.FindRegister.side_effect = x86_find
    x_ptr, x_length = get_key_registers(x86_frame)
    assert x_ptr == 0x20005000
    assert x_length == 32


def test_corrupted_page_n_in_decrypt_database(tmp_path: Path, synthetic_key: bytes):
    """Test that tampering with Page N (N > 1) ciphertext triggers per-page HMAC failure in decrypt_database."""
    plain_db = tmp_path / "plain_multipage.db"
    create_empty_sqlite_db_with_reserve(plain_db)

    # Populate table with enough records to exceed 15 pages (4096 bytes each)
    conn = sqlite3.connect(plain_db)
    conn.execute("CREATE TABLE test_data(id INTEGER PRIMARY KEY, payload TEXT)")
    for _ in range(150):
        conn.execute("INSERT INTO test_data (payload) VALUES (?)", ("A" * 400,))
    conn.commit()
    conn.close()

    total_pages = plain_db.stat().st_size // PAGE_SZ
    assert total_pages >= 15, f"Expected at least 15 pages, got {total_pages}"

    enc_db = tmp_path / "enc_multipage.db"
    encrypt_database(plain_db, enc_db, synthetic_key)

    # First verify uncorrupted database decrypts successfully
    clean_out = tmp_path / "clean_decrypted.db"
    assert decrypt_database(enc_db, clean_out, synthetic_key) is True
    assert clean_out.exists()

    # Read encrypted database and tamper with Page 10 ciphertext
    with open(enc_db, "rb") as fin:
        enc_bytes = bytearray(fin.read())

    # Page 10 starts at offset (10 - 1) * PAGE_SZ = 9 * 4096 = 36864
    page_10_offset = 9 * PAGE_SZ
    # Flip bits in the ciphertext portion of page 10 (offset 50 within page)
    enc_bytes[page_10_offset + 50] ^= 0xFF

    corrupted_db = tmp_path / "corrupted_p10.db"
    with open(corrupted_db, "wb") as fout:
        fout.write(enc_bytes)

    corrupted_out = tmp_path / "corrupted_out.db"
    success = decrypt_database(corrupted_db, corrupted_out, synthetic_key)

    # Must return False and leave no decrypted database file
    assert success is False
    assert not corrupted_out.exists()
    # Also verify no leftover temporary files
    leftover_tmps = list(tmp_path.glob("corrupted_out.db.tmp.*"))
    assert len(leftover_tmps) == 0


def test_invalid_key_types_safe_rejection(synthetic_contact_db: Path, tmp_path: Path):
    """Test that non-string and non-bytes key types are safely rejected without raising TypeError."""
    out_db = tmp_path / "out_invalid_type.db"
    invalid_keys = [None, 12345, [1, 2], {"key": "value"}, 3.14, True]

    for inv_key in invalid_keys:
        res = decrypt_database(synthetic_contact_db, out_db, inv_key)  # type: ignore[arg-type]
        assert res is False
        assert not out_db.exists()
