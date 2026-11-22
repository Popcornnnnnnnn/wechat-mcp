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
Global pytest configuration and synthetic fixtures for wechat-mcp test suites.

Provides synthetic encrypted and decrypted WeChat environments,
FastAPI REST TestClient, FastMCP server emulator with 40 tools,
kqueue event simulator, and mock LLM pipeline backend.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
from typing import Any, Callable, Dict, Generator, List, Literal, Optional, Tuple, Union
from urllib.parse import urlparse
import zlib

from pydantic import BaseModel, Field, ValidationError, field_validator
import pytest

try:
    import zstandard
except ImportError:
    zstandard = None

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from tests.fixtures.crypto_generator import (
    KEY_SZ,
    PAGE_SZ,
    decrypt_database,
    generate_synthetic_encrypted_db,
)
from tests.fixtures.wechat_generator import (
    SUBTYPE_LINK,
    TYPE_APPMSG,
    TYPE_IMAGE,
    TYPE_SYSMSG,
    TYPE_TEXT,
    WCDB_CT_ZSTD,
    SyntheticWeChatFixture,
    md5_table,
)

# ---------------------------------------------------------------------------
# Production Imports and Adapter for E2E Tests
# ---------------------------------------------------------------------------

from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.decompress import decompress_content
from wechat_mcp.mcp.server import create_mcp_server, TOOL_REQUIRED
from wechat_mcp.api.server import create_api_app
from wechat_mcp.watcher.recall import RecallArchive
from wechat_mcp.watcher.kqueue import VnodeWatch, VnodeFlags, WatcherEvent
from wechat_mcp.watcher.journal import EventJournal
from wechat_mcp.summary.pipeline import SummaryPipeline
from wechat_mcp.summary.schema import (
    UnderstandStageSchema,
    Citation,
    CheckStageSchema,
    WriteStageSchema,
    VisualBlock,
    VisualStageSchema,
    SummaryPipelineResult,
)


class MCPServerTestAdapter:
    """Test adapter wrapping real create_mcp_server for synchronous test ergonomics."""

    def __init__(
        self,
        server_or_dir: Union[Any, Path, str, None] = None,
        reader: Optional[HistoryReader] = None,
        recall_archive: Optional[RecallArchive] = None,
        journal: Optional[EventJournal] = None,
        **kwargs: Any,
    ):
        if server_or_dir is not None and hasattr(server_or_dir, "call_tool_sync"):
            self._server = server_or_dir
        else:
            if server_or_dir is not None:
                p = Path(server_or_dir)
                if reader is None and p.is_dir():
                    reader = HistoryReader(p)
                    if recall_archive is None:
                        recall_archive = RecallArchive(p, reader=reader)
                    if journal is None:
                        journal = EventJournal(p / "events.sqlite")
            self._server = create_mcp_server(
                reader=reader,
                recall_archive=recall_archive,
                journal=journal,
                **kwargs,
            )
        self.TOOL_REQUIRED = getattr(self._server, "TOOL_REQUIRED", TOOL_REQUIRED)
        self.subscribers: Dict[str, List[Any]] = {}
        self.reader = getattr(self._server, "reader", None)
        self.recall_archive = getattr(self._server, "recall_archive", None)

    def list_tools(self) -> List[str]:
        return sorted(list(self.TOOL_REQUIRED.keys()))

    def list_tools_sync(self) -> List[str]:
        return sorted(list(self.TOOL_REQUIRED.keys()))

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._server.call_tool_sync(name, arguments)

    def call_tool_sync(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._server.call_tool_sync(name, arguments)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._server, name)


# Backward compatibility aliases for existing test signatures
ReferenceHistoryReader = HistoryReader
ReferenceRecallArchive = RecallArchive
ReferenceKqueueWatcher = VnodeWatch
ReferenceEventJournal = EventJournal
ReferenceSummaryPipeline = SummaryPipeline
ReferenceMCPHandler = MCPServerTestAdapter


def create_reference_fastapi_app(db_dir: Path) -> FastAPI:
    reader = HistoryReader(db_dir)
    return create_api_app(reader=reader)


# ---------------------------------------------------------------------------
# Pytest Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def synthetic_wechat_environment() -> Generator[Path, None, None]:
    """Yields root path of a decrypted synthetic multi-shard WeChat directory."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        fix = SyntheticWeChatFixture(root)
        fix.build_default_dataset(with_reserve=False)
        yield root


@pytest.fixture
def synthetic_encrypted_wechat() -> Generator[Tuple[Path, bytes, Path], None, None]:
    """
    Yields (encrypted_root, enc_key, plain_root) containing 5 encrypted shards
    and encrypted contact/session databases with reserve=80.
    """
    with tempfile.TemporaryDirectory() as td:
        plain_root = Path(td) / "plain"
        enc_root = Path(td) / "enc"
        fix = SyntheticWeChatFixture(plain_root)
        fix.build_default_dataset(with_reserve=True)

        key = os.urandom(KEY_SZ)
        fix.encrypt_all(key, enc_root)
        yield enc_root, key, plain_root


@pytest.fixture
def synthetic_sqlcipher_db() -> Generator[Tuple[Path, Path, bytes, bytes], None, None]:
    """Yields (enc_path, plain_path, test_key, salt)."""
    with tempfile.TemporaryDirectory() as td:
        key = os.urandom(KEY_SZ)
        salt = os.urandom(16)
        enc_path = Path(td) / "test_encrypted.db"
        sql = "CREATE TABLE test(id INT, name TEXT); INSERT INTO test VALUES(1, 'Alice');"
        generate_synthetic_encrypted_db(key, sql_script=sql, output_path=enc_path, salt=salt)
        yield enc_path, enc_path, key, salt


@pytest.fixture
def synthetic_decrypted_db(synthetic_wechat_environment: Path) -> Path:
    """Convenience alias for decrypted synthetic database directory."""
    return synthetic_wechat_environment


@pytest.fixture
def mock_mcp_server(synthetic_wechat_environment: Path) -> MCPServerTestAdapter:
    """Yields an MCP handler instance configured with synthetic databases."""
    reader = HistoryReader(synthetic_wechat_environment)
    recall = RecallArchive(synthetic_wechat_environment, reader=reader)
    journal = EventJournal(synthetic_wechat_environment / "events.sqlite")
    server = create_mcp_server(reader=reader, recall_archive=recall, journal=journal)
    return MCPServerTestAdapter(server)


@pytest.fixture
def mock_api_client(synthetic_wechat_environment: Path) -> Generator[TestClient, None, None]:
    """Yields FastAPI TestClient pointing to synthetic databases."""
    reader = HistoryReader(synthetic_wechat_environment)
    app = create_api_app(reader=reader)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def mock_kqueue() -> Generator[List[Dict[str, Any]], None, None]:
    """Simulated kqueue event log."""
    events: List[Dict[str, Any]] = []
    yield events


@pytest.fixture
def mock_llm_backend() -> Dict[str, Any]:
    """Mock LLM response data adhering to 4-stage pipeline schemas."""
    return {
        "understand": {
            "title": "Understanding Multi-Shard Architectures",
            "summary": "Technical deep dive into temporal partitioning.",
            "entities": ["WeChat", "SQLite", "SQLCipher"],
        },
        "check": {
            "verified": True,
            "citations": [
                {"claim": "Temporal partitioning reduces shard size", "url": "https://example.com/guide"}
            ],
            "rejected_claims": [],
        },
        "write": {
            "editorial_summary": "In this guide, we analyze rolling database shards...",
            "target_tone": "technical",
        },
        "visual": {
            "layout_valid": True,
            "card_template": "default_card",
        },
    }


@pytest.fixture
def mock_summary_pipeline() -> SummaryPipeline:
    """Yields a configured SummaryPipeline instance in mock mode."""
    return SummaryPipeline(mock=True)


# ---------------------------------------------------------------------------
# M1 Synthetic Crypto Fixtures
# ---------------------------------------------------------------------------


def create_empty_sqlite_db_with_reserve(
    path: Path, page_size: int = PAGE_SZ, reserve: int = 80
) -> None:
    """Creates a valid SQLite database file with reserve bytes allocated on page 1."""
    usable_size = page_size - reserve
    header = bytearray(page_size)
    header[0:16] = b"SQLite format 3\x00"
    header[16:18] = page_size.to_bytes(2, "big")
    header[18] = 1
    header[19] = 1
    header[20] = reserve
    header[21] = 64
    header[22] = 32
    header[23] = 32
    header[24:28] = (1).to_bytes(4, "big")
    header[28:32] = (1).to_bytes(4, "big")
    header[44:48] = (4).to_bytes(4, "big")
    header[56:60] = (1).to_bytes(4, "big")
    header[92:96] = (1).to_bytes(4, "big")

    # Page 1 B-tree header (offset 100)
    header[100] = 0x0D
    header[101:103] = (0).to_bytes(2, "big")
    header[103:105] = (0).to_bytes(2, "big")
    header[105:107] = usable_size.to_bytes(2, "big")
    header[107] = 0

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)


@pytest.fixture
def synthetic_key() -> bytes:
    """Returns a deterministic 32-byte AES key for testing."""
    return b"0123456789abcdef0123456789abcdef"


@pytest.fixture
def synthetic_contact_db(tmp_path: Path, synthetic_key: bytes) -> Path:
    """Generates an encrypted synthetic contact.db with reserve=80."""
    from wechat_mcp.crypto.decrypt import encrypt_database

    plain_db = tmp_path / "plain_contact.db"
    create_empty_sqlite_db_with_reserve(plain_db)

    conn = sqlite3.connect(plain_db)
    conn.execute("""
        CREATE TABLE contact(
            id INTEGER PRIMARY KEY,
            username TEXT,
            local_type INTEGER,
            alias TEXT,
            encrypt_username TEXT,
            flag INTEGER,
            delete_flag INTEGER,
            verify_flag INTEGER,
            remark TEXT,
            remark_quan_pin TEXT,
            remark_pin_yin_initial TEXT,
            nick_name TEXT,
            pin_yin_initial TEXT,
            quan_pin TEXT,
            big_head_url TEXT,
            small_head_url TEXT,
            head_img_md5 TEXT,
            chat_room_notify INTEGER,
            is_in_chat_room INTEGER,
            description TEXT,
            extra_buffer BLOB,
            chat_room_type INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE chat_room(
            id INTEGER PRIMARY KEY,
            username TEXT,
            owner TEXT,
            ext_buffer BLOB
        )
    """)
    conn.execute(
        "INSERT INTO contact (id, username, nick_name, remark) VALUES (1, 'wxid_mock_alice', 'Alice Wonderland', 'Alice')"
    )
    conn.execute(
        "INSERT INTO contact (id, username, nick_name, remark) VALUES (2, 'wxid_mock_bob', 'Bob Smith', 'Bob')"
    )
    conn.execute(
        "INSERT INTO contact (id, username, nick_name, remark) VALUES (3, 'mock_group@chatroom', 'Test Group', '')"
    )
    conn.execute(
        "INSERT INTO chat_room (id, username, owner) VALUES (1, 'mock_group@chatroom', 'wxid_mock_alice')"
    )
    conn.commit()
    conn.close()

    cipher_db = tmp_path / "contact" / "contact.db"
    encrypt_database(plain_db, cipher_db, synthetic_key)
    return cipher_db


@pytest.fixture
def synthetic_session_db(tmp_path: Path, synthetic_key: bytes) -> Path:
    """Generates an encrypted synthetic session.db."""
    from wechat_mcp.crypto.decrypt import encrypt_database

    plain_db = tmp_path / "plain_session.db"
    create_empty_sqlite_db_with_reserve(plain_db)

    conn = sqlite3.connect(plain_db)
    conn.execute("""
        CREATE TABLE SessionTable(
            username TEXT PRIMARY KEY,
            type INTEGER,
            unread_count INTEGER,
            unread_first_msg_srv_id INTEGER,
            unread_first_pat_msg_local_id INTEGER,
            unread_first_pat_msg_sort_seq INTEGER,
            is_hidden INTEGER,
            summary TEXT,
            draft TEXT,
            status INTEGER,
            last_timestamp INTEGER,
            sort_timestamp INTEGER,
            last_clear_unread_timestamp INTEGER,
            last_msg_locald_id INTEGER,
            last_msg_type INTEGER,
            last_msg_sub_type INTEGER,
            last_msg_sender TEXT,
            last_sender_display_name TEXT,
            last_msg_ext_type INTEGER
        )
    """)
    conn.execute(
        "INSERT INTO SessionTable (username, unread_count, summary, last_timestamp) VALUES ('wxid_mock_alice', 0, 'Hello!', 1700000000)"
    )
    conn.execute(
        "INSERT INTO SessionTable (username, unread_count, summary, last_timestamp) VALUES ('mock_group@chatroom', 2, 'Group update', 1700000050)"
    )
    conn.commit()
    conn.close()

    cipher_db = tmp_path / "session" / "session.db"
    encrypt_database(plain_db, cipher_db, synthetic_key)
    return cipher_db


@pytest.fixture
def synthetic_message_db(tmp_path: Path, synthetic_key: bytes) -> Path:
    """Generates an encrypted synthetic message_0.db with Name2Id and Msg tables."""
    from wechat_mcp.crypto.decrypt import encrypt_database

    plain_db = tmp_path / "plain_message_0.db"
    create_empty_sqlite_db_with_reserve(plain_db)

    conn = sqlite3.connect(plain_db)
    conn.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER)")
    conn.execute("INSERT INTO Name2Id (user_name, is_session) VALUES ('wxid_mock_alice', 1)")

    alice_hash = hashlib.md5(b"wxid_mock_alice").hexdigest()
    conn.execute(f"""
        CREATE TABLE Msg_{alice_hash}(
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
        )
    """)
    conn.execute(
        f"INSERT INTO Msg_{alice_hash} (server_id, local_type, create_time, message_content) VALUES (101, 1, 1700000000, 'Hi there!')"
    )
    conn.commit()
    conn.close()

    cipher_db = tmp_path / "message" / "message_0.db"
    encrypt_database(plain_db, cipher_db, synthetic_key)
    return cipher_db


@pytest.fixture
def synthetic_storage_tree(tmp_path: Path, synthetic_key: bytes) -> Tuple[Path, Path]:
    """Generates a complete mock WeChat storage directory and matching all_keys.json."""
    from wechat_mcp.crypto.decrypt import encrypt_database

    db_storage = tmp_path / "xwechat_files" / "wxid_dummy_user" / "db_storage"
    db_storage.mkdir(parents=True, exist_ok=True)

    plain_contact = tmp_path / "plain_contact.db"
    create_empty_sqlite_db_with_reserve(plain_contact)
    c1 = sqlite3.connect(plain_contact)
    c1.execute("CREATE TABLE contact(id INTEGER PRIMARY KEY, username TEXT, nick_name TEXT)")
    c1.execute("INSERT INTO contact VALUES (1, 'wxid_mock_alice', 'Alice Wonderland')")
    c1.commit()
    c1.close()

    cipher_contact = db_storage / "contact" / "contact.db"
    encrypt_database(plain_contact, cipher_contact, synthetic_key)

    keys_file = tmp_path / "all_keys.json"
    keys_data = {
        "contact/contact.db": {
            "enc_key": synthetic_key.hex(),
            "salt": "0" * 32,
            "status": "verified",
        }
    }
    with open(keys_file, "w") as f:
        json.dump(keys_data, f, indent=2)

    return db_storage, keys_file
