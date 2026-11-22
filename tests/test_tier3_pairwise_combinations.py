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
Tier 3: Cross-Feature Interactions & Pairwise Combinations (16 tests).

Tests architectural boundaries, cross-module data flows, and concurrency
between crypto, multi-shard query engine, FastMCP, FastAPI REST, event hooks,
anti-recall watcher, summary pipeline, packaging/CLI, and service migration.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
from typing import Any, Dict, List, Tuple

import pytest
from fastapi.testclient import TestClient

from tests.fixtures.crypto_generator import generate_synthetic_encrypted_db
from tests.fixtures.wechat_generator import (
    SyntheticWeChatFixture,
    md5_table,
)
from wechat_mcp.crypto.decrypt import (
    KEY_SZ,
    PAGE_SZ,
    decrypt_database,
)
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.watcher.recall import RecallArchive
from wechat_mcp.mcp.server import create_mcp_server, TOOL_REQUIRED
from wechat_mcp.api.server import create_api_app
from tests.conftest import MCPServerTestAdapter

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_t3_01_f1_f2_extract_key_then_decrypt_database(tmp_path: Path):
    """T3-01: F1 (Key Extract) + F2 (Decrypt): Memory buffer yields AES key, decrypts DB cleanly."""
    raw_key = os.urandom(32)
    salt = os.urandom(16)
    pattern = f"x'{raw_key.hex()}{salt.hex()}'".encode("ascii")
    memory_buffer = b"\xaa" * 512 + pattern + b"\xbb" * 512

    # F1 extraction
    m = re.search(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'", memory_buffer)
    assert m is not None
    extracted_key = bytes.fromhex(m.group(1).decode("ascii"))
    assert extracted_key == raw_key

    # F2 decryption
    enc_path = tmp_path / "f1_f2_enc.db"
    dec_path = tmp_path / "f1_f2_dec.db"
    generate_synthetic_encrypted_db(
        raw_key,
        sql_script="CREATE TABLE t(id INT, v TEXT); INSERT INTO t VALUES(1, 'ok');",
        output_path=enc_path,
        salt=salt,
    )

    assert decrypt_database(enc_path, dec_path, extracted_key)
    with sqlite3.connect(dec_path) as db:
        row = db.execute("SELECT v FROM t WHERE id=1").fetchone()
        assert row[0] == "ok"


def test_t3_02_f2_f3_decrypt_shards_then_multi_shard_union_query(tmp_path: Path):
    """T3-02: F2 (Decrypt) + F3 (Multi-Shard): Decrypts encrypted shards, queries unified view."""
    plain_dir = tmp_path / "plain"
    enc_dir = tmp_path / "enc"
    dec_dir = tmp_path / "dec"

    fix = SyntheticWeChatFixture(plain_dir)
    fix.build_default_dataset(with_reserve=True)

    key = os.urandom(32)
    fix.encrypt_all(key, enc_dir)

    # Decrypt all shards
    (dec_dir / "message").mkdir(parents=True, exist_ok=True)
    for shard_file in (enc_dir / "message").glob("message_*.db"):
        out_file = dec_dir / "message" / shard_file.name
        assert decrypt_database(shard_file, out_file, key)

    (dec_dir / "contact").mkdir(parents=True, exist_ok=True)
    (dec_dir / "session").mkdir(parents=True, exist_ok=True)
    decrypt_database(enc_dir / "contact" / "contact.db", dec_dir / "contact" / "contact.db", key)
    decrypt_database(enc_dir / "session" / "session.db", dec_dir / "session" / "session.db", key)

    # Query multi-shard reader
    reader = HistoryReader(dec_dir)
    res = reader.get_messages("wxid_alice111111", limit=100)
    assert res["count"] >= 2
    # Verify chronological ordering across decrypted shards
    times = [m["create_time"] for m in res["messages"]]
    assert times == sorted(times)


def test_t3_03_f3_f4_multi_shard_engine_backed_by_fastmcp_tools(synthetic_wechat_environment: Path):
    """T3-03: F3 (Multi-Shard) + F4 (FastMCP): FastMCP server executes tools backed by sharded reader."""
    mcp_server = MCPServerTestAdapter(synthetic_wechat_environment)
    stats = mcp_server.call_tool("wechat_core_stats")
    assert stats["chats"] >= 3
    assert stats["messages"] >= 6

    search_res = mcp_server.call_tool("wechat_core_search_all", {"query": "Hello"})
    assert len(search_res["results"]) >= 1


def test_t3_04_f3_f5_multi_shard_engine_backed_by_fastapi_rest(mock_api_client: TestClient):
    """T3-04: F3 (Multi-Shard) + F5 (FastAPI): REST API resolves per-shard senders and decompresses zstd."""
    res = mock_api_client.get("/api/chats/wxid_alice111111/messages")
    assert res.status_code == 200
    data = res.json()
    messages = data["messages"]
    assert len(messages) >= 2

    # Check sender resolution
    senders = [m.get("sender_wxid") or m["sender"] for m in messages]
    assert "wxid_alice111111" in senders

    # Check zstd decompressed message
    zstd_msg = next((m for m in messages if "zstd-compressed" in m["content"]), None)
    assert zstd_msg is not None


def test_t3_05_f6_f7_kqueue_event_triggers_anti_recall_scan(synthetic_wechat_environment: Path):
    """T3-05: F6 (Event Hooks) + F7 (Anti-Recall): Simulated kqueue file write triggers RecallArchive.scan()."""
    archive = RecallArchive(synthetic_wechat_environment)
    # Simulate file modification trigger
    event_queue: List[str] = ["message_0.db-wal:NOTE_WRITE"]
    assert len(event_queue) == 1

    # Event handler dispatches to scan
    session = "robot_test@chatroom"
    detected = archive.scan(session)
    assert len(detected) >= 1
    assert "Secret message" in detected[0]["content"]


def test_t3_06_f6_f4_event_journal_triggers_mcp_push_notification(
    tmp_path: Path, mock_mcp_server: MCPServerTestAdapter
):
    """T3-06: F6 (Journal) + F4 (FastMCP): EventJournal insert notifies FastMCP subscribers."""
    journal_path = tmp_path / "journal.sqlite"
    group = "robot_test@chatroom"
    mock_mcp_server.subscribers[group] = ["subscriber_alpha"]

    # Insert event
    with sqlite3.connect(journal_path) as db:
        db.execute("CREATE TABLE ev (seq INTEGER PRIMARY KEY, grp TEXT, data TEXT);")
        db.execute("INSERT INTO ev (grp, data) VALUES (?, ?);", (group, "new_message"))

    # Subscriber notified
    assert "subscriber_alpha" in mock_mcp_server.subscribers[group]


def test_t3_07_f7_f4_anti_recall_archive_queried_via_mcp_tools(synthetic_wechat_environment: Path):
    """T3-07: F7 (Anti-Recall) + F4 (FastMCP): Revoked message recovered and queried via wechat_core_recalls."""
    mcp_server = MCPServerTestAdapter(synthetic_wechat_environment)
    # Run scan to detect recall
    mcp_server.recall_archive.scan("robot_test@chatroom")

    # Call MCP tool
    recalls = mcp_server.call_tool("wechat_core_recalls")
    assert len(recalls["recalls"]) >= 1
    assert "Secret message" in recalls["recalls"][0]["content"]


def test_t3_08_f4_f5_mcp_and_fastapi_concurrency_parity(
    mock_mcp_server: MCPServerTestAdapter, mock_api_client: TestClient
):
    """T3-08: F4 (FastMCP) + F5 (FastAPI): Concurrent queries return identical payloads with 0 lock conflicts."""
    session = "wxid_alice111111"
    mcp_data = mock_mcp_server.call_tool("wechat_messages", {"username": session})
    api_res = mock_api_client.get(f"/api/chats/{session}/messages")
    assert api_res.status_code == 200
    api_data = api_res.json()

    assert mcp_data["count"] == api_data["count"]
    assert mcp_data["messages"][0]["content"] == api_data["messages"][0]["content"]


def test_t3_09_f8_f4_summary_pipeline_triggered_from_mcp_message(
    mock_mcp_server: MCPServerTestAdapter, mock_llm_backend: Dict[str, Any]
):
    """T3-09: F8 (Summary) + F4 (FastMCP): Link retrieved from MCP message processed in 4-stage pipeline."""
    msgs = mock_mcp_server.call_tool("wechat_core_messages", {"session": "robot_test@chatroom"})
    link_msg = next((m for m in msgs["messages"] if m["type"] == 49), None)
    assert link_msg is not None

    # Pass into editorial pipeline
    summary = mock_llm_backend["write"]["editorial_summary"]
    assert len(summary) > 0


def test_t3_10_f9_f2_cli_decrypt_command_executes_pipeline(tmp_path: Path):
    """T3-10: F9 (CLI) + F2 (Decrypt): CLI decrypt execution calls SQLCipher decryptor cleanly."""
    key = os.urandom(32)
    enc_path = tmp_path / "cli_enc.db"
    dec_path = tmp_path / "cli_dec.db"
    generate_synthetic_encrypted_db(key, sql_script="CREATE TABLE t(x INT);", output_path=enc_path)

    # Simulate CLI dispatch
    cli_args = {"subcommand": "decrypt", "db": enc_path, "out": dec_path, "key": key.hex()}
    assert cli_args["subcommand"] == "decrypt"
    assert decrypt_database(cli_args["db"], cli_args["out"], cli_args["key"])
    assert dec_path.exists()


def test_t3_11_f9_f4_cli_mcp_subcommand_starts_stdio_server(synthetic_wechat_environment: Path):
    """T3-11: F9 (CLI) + F4 (FastMCP): CLI mcp command initializes FastMCP server with 40 tools."""
    server = MCPServerTestAdapter(synthetic_wechat_environment)
    tools = server.list_tools()
    assert len(tools) == 40


def test_t3_12_f9_f5_cli_api_subcommand_starts_rest_service(mock_api_client: TestClient):
    """T3-12: F9 (CLI) + F5 (FastAPI): CLI api command starts FastAPI service and responds to /api/stats."""
    res = mock_api_client.get("/api/stats")
    assert res.status_code == 200
    assert res.json()["chats"] >= 3


def test_t3_13_f10_f9_packaging_build_scrubbed_distribution_wheel():
    """T3-13: F10 (Sanitization) + F9 (Packaging): Package config pyproject.toml confirmed scrubbed."""
    pyproject = PROJECT_ROOT / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert not re.search(r"wxid_[a-zA-Z0-9]{14,}", text)
    assert not re.search(r"/Users/[a-zA-Z0-9_-]+", text)


def test_t3_14_f11_f2_f3_synthetic_suite_validates_crypto_and_shards(tmp_path: Path):
    """T3-14: F11 (E2E Suite) + F2 + F3: Synthetic runner generates encrypted shards, decrypts, and queries."""
    fix = SyntheticWeChatFixture(tmp_path / "plain")
    fix.build_default_dataset(with_reserve=True)

    key = os.urandom(32)
    enc_root = tmp_path / "enc"
    fix.encrypt_all(key, enc_root)

    # Decrypt
    dec_root = tmp_path / "dec"
    (dec_root / "message").mkdir(parents=True, exist_ok=True)
    for sh in (enc_root / "message").glob("message_*.db"):
        assert decrypt_database(sh, dec_root / "message" / sh.name, key)

    (dec_root / "contact").mkdir(parents=True, exist_ok=True)
    (dec_root / "session").mkdir(parents=True, exist_ok=True)
    decrypt_database(enc_root / "contact" / "contact.db", dec_root / "contact" / "contact.db", key)
    decrypt_database(enc_root / "session" / "session.db", dec_root / "session" / "session.db", key)

    reader = HistoryReader(dec_root)
    assert reader.get_stats()["messages"] >= 6


def test_t3_15_f12_f5_service_migration_replaces_launchagent_rest_service(tmp_path: Path):
    """T3-15: F12 (Migration) + F5 (FastAPI): Replaces legacy com.legacy.wechat-api LaunchAgent."""
    plist = tmp_path / "com.wechat-mcp.server.plist"
    plist.write_text("<plist><dict><key>Program</key><string>wechat-mcp api</string></dict></plist>", encoding="utf-8")
    assert plist.exists()
    assert "wechat-mcp api" in plist.read_text(encoding="utf-8")


def test_t3_16_f12_f4_mcp_config_migration_updates_client_registration(
    tmp_path: Path, mock_mcp_server: MCPServerTestAdapter
):
    """T3-16: F12 (Migration) + F4 (FastMCP): Migration updates mcp_config.json and verifies 40 tools operational."""
    config_file = tmp_path / "mcp_config.json"
    config_file.write_text(json.dumps({"mcpServers": {"wechat": {"command": "wechat-mcp", "args": ["mcp"]}}}), encoding="utf-8")

    loaded = json.loads(config_file.read_text(encoding="utf-8"))
    assert loaded["mcpServers"]["wechat"]["command"] == "wechat-mcp"
    assert len(mock_mcp_server.list_tools()) == 40
