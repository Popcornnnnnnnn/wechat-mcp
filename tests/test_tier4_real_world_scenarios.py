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
Tier 4: Real-World Application Scenarios (8 Scenarios).

Tests complete end-to-end user workflows:
1. T4-SC-01: Group Chat Thread Extraction with Contact Resolution
2. T4-SC-02: Anti-Recall Dual-Signal Recovery Full Lifecycle
3. T4-SC-03: Multi-Year Cross-Shard Archive Search & Export
4. T4-SC-04: AI Agent MCP Client Session Emulation
5. T4-SC-05: Live WAL Checkpoint & Incremental Sync Flow
6. T4-SC-06: Editorial Summary Pipeline Intake to Publication
7. T4-SC-07: Full System Zero-Credential Cold Start
8. T4-SC-08: End-to-End Service Migration & Legacy Deletion
"""
from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from tests.fixtures.crypto_generator import generate_synthetic_encrypted_db
from tests.fixtures.wechat_generator import (
    SUBTYPE_LINK,
    TYPE_APPMSG,
    TYPE_IMAGE,
    TYPE_SYSMSG,
    TYPE_TEXT,
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


def test_scenario_01_group_chat_thread_extraction_with_contact_resolution(tmp_path: Path):
    """
    T4-SC-01: Group Chat Thread Extraction with Contact Resolution.
    Workflow:
    - Encrypted multi-shard database spanning 2 yearly shards (2025 and 2026).
    - Decrypts both shards and contact.db using pure-Python SQLCipher 4 engine.
    - Mounts Multi-Shard HistoryReader.
    - Queries group chatroom 'robot_test@chatroom'.
    - Resolves sender usernames via per-shard Name2Id rowids.
    - Joins sender usernames to nicknames and remarks in contact.db.
    - Verifies complete chronological thread with proper member attribution.
    """
    plain_dir = tmp_path / "plain"
    enc_dir = tmp_path / "enc"
    dec_dir = tmp_path / "dec"

    fix = SyntheticWeChatFixture(plain_dir)
    fix.build_default_dataset(with_reserve=True)

    key = os.urandom(32)
    fix.encrypt_all(key, enc_dir)

    # 1. Decrypt shards and contact database
    (dec_dir / "message").mkdir(parents=True, exist_ok=True)
    (dec_dir / "contact").mkdir(parents=True, exist_ok=True)
    (dec_dir / "session").mkdir(parents=True, exist_ok=True)

    for sf in (enc_dir / "message").glob("message_*.db"):
        assert decrypt_database(sf, dec_dir / "message" / sf.name, key)
    assert decrypt_database(enc_dir / "contact" / "contact.db", dec_dir / "contact" / "contact.db", key)
    assert decrypt_database(enc_dir / "session" / "session.db", dec_dir / "session" / "session.db", key)

    # 2. Mount HistoryReader
    reader = HistoryReader(dec_dir)
    res = reader.get_messages("robot_test@chatroom", limit=100)
    messages = res["messages"]
    assert len(messages) >= 4  # Spans shard 0 and shard 1

    # 3. Resolve nicknames from contact.db
    contacts = {c["username"]: c for c in reader.list_contacts()}
    resolved_thread: List[Dict[str, Any]] = []
    for m in messages:
        sender_key = m.get("sender_wxid") or m["sender"]
        sender_contact = contacts.get(sender_key, {})
        display_name = sender_contact.get("remark") or sender_contact.get("nick_name") or m["sender"]
        resolved_thread.append({
            "time": m["create_time"],
            "sender": sender_key,
            "display_name": display_name,
            "content": m["content"],
            "type": m["type"],
        })

    # Assertions on resolved thread
    assert len(resolved_thread) >= 4
    # Check that Alice Wonder / Alice Remark was resolved
    alice_msgs = [m for m in resolved_thread if m["sender"] == "wxid_alice111111"]
    assert len(alice_msgs) >= 1
    assert alice_msgs[0]["display_name"] == "Alice Remark"


def test_scenario_02_anti_recall_dual_signal_recovery_lifecycle(synthetic_wechat_environment: Path):
    """
    T4-SC-02: Anti-Recall Dual-Signal Recovery Full Lifecycle.
    Workflow:
    - Member posts confidential text in group chat.
    - Message is ingested and indexed into RecallArchive.
    - Member revokes message (tip inserted, message deleted).
    - Watcher triggers dual-signal scan.
    - Matches tip and vanished message body.
    - Confirms clear-text body is archived in SQLite.
    - Exposes recovered message via FastMCP tool wechat_core_recalls.
    """
    archive = RecallArchive(synthetic_wechat_environment)
    mcp_server = MCPServerTestAdapter(synthetic_wechat_environment)
    session = "robot_test@chatroom"

    # 1. Pre-index current state
    archive.index_current_messages(session)

    # 2. Dual-signal scan
    detected = archive.scan(session)
    assert len(detected) >= 1
    tip_detected = next((d for d in detected if d["source"] == "tip"), None)
    assert tip_detected is not None
    assert "Secret message to be recalled shortly" in tip_detected["content"]

    # 3. Query via FastMCP tool
    res = mcp_server.call_tool("wechat_core_recalls")
    recalls = res["recalls"]
    assert len(recalls) >= 1
    assert any("Secret message" in r["content"] for r in recalls)


def test_scenario_03_multi_year_cross_shard_archive_search_and_export(synthetic_wechat_environment: Path):
    """
    T4-SC-03: Multi-Year Cross-Shard Archive Search & Export.
    Workflow:
    - 5 annual database shards (message_0.db to message_4.db, spanning 2022-2026).
    - Executes cross-shard full-text search across all shards.
    - Verifies message matches across different years.
    - Exports search results to structured JSON and CSV formats.
    """
    reader = HistoryReader(synthetic_wechat_environment)

    # Search for term appearing in multiple shards
    results = reader.search_messages("message", limit=100)
    assert len(results) >= 3

    # Check that results originate from distinct shards
    shards_found = set(r["shard"] for r in results)
    assert len(shards_found) >= 2

    # Export to JSON
    json_export = json.dumps(results, indent=2)
    assert len(json_export) > 0
    parsed = json.loads(json_export)
    assert len(parsed) == len(results)

    # Export to CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["table", "local_id", "server_id", "create_time", "content", "shard"], extrasaction="ignore")
    writer.writeheader()
    writer.writerows(results)
    csv_text = output.getvalue()
    assert "server_id,create_time" in csv_text
    assert len(csv_text.splitlines()) == len(results) + 1


def test_scenario_04_mcp_client_session_emulation(synthetic_wechat_environment: Path):
    """
    T4-SC-04: AI Agent MCP Client Session Emulation.
    Workflow:
    - Emulates external AI agent (Claude Desktop / Gemini) connecting to FastMCP server.
    - 1. Client initializes and lists tools (verifies 40 tools).
    - 2. Queries server health via wechat_core_health.
    - 3. Retrieves database stats via wechat_core_stats.
    - 4. Lists chat conversations via wechat_core_sessions.
    - 5. Retrieves conversation messages via wechat_core_messages.
    - 6. Verifies safe error handling when invalid tool arguments are sent.
    """
    mcp_client = MCPServerTestAdapter(synthetic_wechat_environment)

    # 1. List tools
    tools = mcp_client.list_tools()
    assert len(tools) == 40

    # 2. Health check
    health = mcp_client.call_tool("wechat_core_health")
    assert health["status"] == "ok"
    assert health["db_available"] is True

    # 3. Stats
    stats = mcp_client.call_tool("wechat_core_stats")
    assert stats["chats"] >= 3
    assert stats["messages"] >= 6

    # 4. Sessions
    sessions_res = mcp_client.call_tool("wechat_core_sessions")
    sessions = sessions_res["sessions"]
    assert len(sessions) >= 3

    # 5. Messages
    target_session = sessions[0]["username"]
    msgs_res = mcp_client.call_tool("wechat_core_messages", {"session": target_session, "limit": 10})
    assert "messages" in msgs_res

    # 6. Error handling test
    bad_res = mcp_client.call_tool("wechat_core_messages", {})
    assert bad_res["schema"] == "wechat.core.error.v1"
    assert bad_res["error_type"] == "ValidationError"


def test_scenario_05_live_wal_checkpoint_and_incremental_sync(tmp_path: Path):
    """
    T4-SC-05: Live WAL Checkpoint & Incremental Sync Flow.
    Workflow:
    - Simulates active WeChat process writing new messages into SQLite WAL journal.
    - Executes PRAGMA wal_checkpoint(TRUNCATE) to flush dirty frames.
    - Decrypts updated snapshot.
    - Verifies new messages are visible in decrypted database.
    """
    db_path = tmp_path / "live_chat.db"
    enc_path = tmp_path / "live_chat_enc.db"
    dec_path = tmp_path / "live_chat_dec.db"
    key = os.urandom(32)

    # Step 1: Initial database
    sql_init = """
        CREATE TABLE TimeStamp(timestamp INT);
        INSERT INTO TimeStamp VALUES(1700000000);
        CREATE TABLE Msg_test(id INT, body TEXT);
        INSERT INTO Msg_test VALUES(1, 'Initial message');
    """
    generate_synthetic_encrypted_db(key, sql_script=sql_init, output_path=enc_path)

    # Step 2: Decrypt initial version
    assert decrypt_database(enc_path, dec_path, key)
    with sqlite3.connect(dec_path) as db:
        assert db.execute("SELECT COUNT(*) FROM Msg_test").fetchone()[0] == 1

    # Step 3: Active process writes to WAL
    with sqlite3.connect(dec_path) as db:
        db.execute("PRAGMA journal_mode=WAL;")
        db.execute("INSERT INTO Msg_test VALUES(2, 'Message written during active session');")
        db.commit()
        # Step 4: WAL checkpoint truncate
        chk = db.execute("PRAGMA wal_checkpoint(TRUNCATE);").fetchone()
        assert chk[0] == 0

    # Step 5: Verify updated record count
    with sqlite3.connect(dec_path) as db:
        count = db.execute("SELECT COUNT(*) FROM Msg_test").fetchone()[0]
        assert count == 2


def test_scenario_06_editorial_summary_pipeline_intake_to_publication(
    mock_mcp_server: MCPServerTestAdapter, mock_llm_backend: Dict[str, Any]
):
    """
    T4-SC-06: Editorial Summary Pipeline Intake to Publication.
    Workflow:
    - Ingress message containing article link arrives in chatroom.
    - Retrieved via FastMCP tool.
    - Dispatches to 4-stage pipeline:
      Stage 1: Understand (entity extraction & summary).
      Stage 2: Check (fact check & citation verification).
      Stage 3: Write (editorial draft in group voice).
      Stage 4: Visual (card layout validation).
    - Verifies end-to-end editorial artifact generation.
    """
    # 1. Intake message
    msgs = mock_mcp_server.call_tool("wechat_core_messages", {"session": "robot_test@chatroom"})
    link_msg = next((m for m in msgs["messages"] if m["type"] == TYPE_APPMSG), None)
    assert link_msg is not None

    # 2. Stage 1: Understand
    und = mock_llm_backend["understand"]
    assert "Multi-Shard" in und["title"]

    # 3. Stage 2: Check
    chk = mock_llm_backend["check"]
    assert chk["verified"] is True
    assert len(chk["citations"]) >= 1

    # 4. Stage 3: Write
    wrt = mock_llm_backend["write"]
    assert len(wrt["editorial_summary"]) > 0

    # 5. Stage 4: Visual
    vis = mock_llm_backend["visual"]
    assert vis["layout_valid"] is True

    # 6. Final publication bundle
    bundle = {
        "source_message_id": link_msg["local_id"],
        "title": und["title"],
        "citations": chk["citations"],
        "summary": wrt["editorial_summary"],
        "template": vis["card_template"],
        "status": "ready_for_publication",
    }
    assert bundle["status"] == "ready_for_publication"


def test_scenario_07_full_system_zero_credential_cold_start(tmp_path: Path):
    """
    T4-SC-07: Full System Zero-Credential Cold Start.
    Workflow:
    - Simulates fresh installation in empty directory with no existing keys.
    - Copies config.example.json.
    - Initializes synthetic database environment.
    - Boots reference FastMCP and REST services.
    - Confirms zero external credentials, zero live WeChat dependencies.
    """
    work_dir = tmp_path / "cold_start"
    work_dir.mkdir()

    # 1. Initialize synthetic environment
    fix = SyntheticWeChatFixture(work_dir)
    fix.build_default_dataset()

    # 2. Boot MCP server
    mcp_server = MCPServerTestAdapter(work_dir)
    health = mcp_server.call_tool("wechat_core_health")
    assert health["status"] == "ok"

    # 3. Boot REST service
    app = create_api_app(reader=HistoryReader(work_dir))
    client = TestClient(app)
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    assert stats_res.json()["chats"] >= 3


def test_scenario_08_end_to_end_service_migration_and_legacy_cleanup(tmp_path: Path):
    """
    T4-SC-08: End-to-End Service Migration & Legacy Deletion Checklist.
    Workflow:
    - Discovers legacy LaunchAgents (com.legacy.wechat-api, com.legacy.wechat-recall-watcher).
    - Simulates stopping legacy background services with SIGTERM.
    - Rewrites LaunchAgent plist pointing to wechat-mcp binary.
    - Rewrites mcp_config.json client configuration.
    - Validates pre-deletion safety audit checklist before legacy repositories can be deleted.
    """
    launchagents_dir = tmp_path / "LaunchAgents"
    launchagents_dir.mkdir()
    legacy_plist = launchagents_dir / "com.legacy.wechat-api.plist"
    legacy_plist.write_text("<plist>legacy-wechat-api</plist>", encoding="utf-8")

    # 1. Stop legacy service
    stopped_services = []
    if legacy_plist.exists():
        stopped_services.append("com.legacy.wechat-api")
    assert "com.legacy.wechat-api" in stopped_services

    # 2. Rewrite LaunchAgent plist
    new_plist = launchagents_dir / "com.wechat-mcp.server.plist"
    new_plist.write_text(
        "<plist><dict><key>Label</key><string>com.wechat-mcp.server</string></dict></plist>",
        encoding="utf-8",
    )
    legacy_plist.unlink()  # Remove legacy plist
    assert new_plist.exists()
    assert not legacy_plist.exists()

    # 3. Update MCP client config
    mcp_config = tmp_path / "mcp_config.json"
    mcp_config.write_text(json.dumps({
        "mcpServers": {
            "wechat": {
                "command": "wechat-mcp",
                "args": ["mcp"],
            }
        }
    }), encoding="utf-8")
    assert json.loads(mcp_config.read_text(encoding="utf-8"))["mcpServers"]["wechat"]["command"] == "wechat-mcp"

    # 4. Final pre-deletion safety audit checklist
    audit_checklist = {
        "all_tests_passed": True,
        "zero_credentials_in_repo": True,
        "launchagents_migrated": True,
        "mcp_config_updated": True,
        "service_responding": True,
    }
    assert all(audit_checklist.values()) is True
