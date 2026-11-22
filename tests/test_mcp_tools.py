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

"""Unit tests for FastMCP server tool surface, parameter validation, error envelopes, and legacy parity."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sqlite3

import pytest

from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.shards import md5_table
from wechat_mcp.mcp.errors import ERROR_SCHEMA, redact_sensitive, safe_error
from wechat_mcp.mcp.push import EventPush
from wechat_mcp.mcp.server import TOOL_REQUIRED, create_mcp_server


@pytest.fixture
def test_reader(tmp_path: Path) -> HistoryReader:
    """Fixture providing a HistoryReader on synthetic data."""
    db_storage = tmp_path / "db_storage"
    msg_dir = db_storage / "message"
    contact_dir = db_storage / "contact"
    session_dir = db_storage / "session"
    msg_dir.mkdir(parents=True)
    contact_dir.mkdir(parents=True)
    session_dir.mkdir(parents=True)

    with sqlite3.connect(contact_dir / "contact.db") as db:
        db.execute("CREATE TABLE contact(id INT, username TEXT, alias TEXT, remark TEXT, nick_name TEXT);")
        db.execute("INSERT INTO contact VALUES(1, 'wxid_test1', 'alias1', 'Remark1', 'Nick1');")
        db.commit()

    with sqlite3.connect(session_dir / "session.db") as db:
        db.execute("CREATE TABLE SessionTable(username TEXT, type INT, unread_count INT, summary TEXT, last_timestamp INT, last_msg_sender TEXT);")
        db.execute("INSERT INTO SessionTable VALUES('wxid_test1', 1, 0, 'hello', 1700000000, 'wxid_test1');")
        db.commit()

    tname = md5_table("wxid_test1")
    with sqlite3.connect(msg_dir / "message_0.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1700000000);")
        db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER);")
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(1, 'wxid_test1', 0);")
        db.execute(f"""
            CREATE TABLE "{tname}"(
                local_id INT, server_id INT, local_type INT, sort_seq INT,
                real_sender_id INT, create_time INT, status INT, source TEXT,
                message_content TEXT, compress_content TEXT,
                WCDB_CT_message_content INT, WCDB_CT_source INT
            );
        """)
        db.execute(f'INSERT INTO "{tname}" VALUES(1, 101, 1, 10, 1, 1700000000, 2, "", "Test message content", NULL, 0, 0);')
        db.commit()

    return HistoryReader(db_storage)


def test_all_40_tools_registered(test_reader: HistoryReader):
    """Test FastMCP server advertises exactly 40 tools (30 Core + 10 legacy aliases)."""
    server = create_mcp_server(reader=test_reader)
    tools = asyncio.run(server.list_tools())
    assert len(tools) == 40

    tool_names = set(t.name for t in tools)
    assert len(tool_names) == 40
    assert tool_names == set(TOOL_REQUIRED.keys())

    # Check key core tools
    assert "wechat_core_health" in tool_names
    assert "wechat_core_sessions" in tool_names
    assert "wechat_core_stats" in tool_names
    assert "wechat_core_messages" in tool_names
    assert "wechat_core_search" in tool_names
    assert "wechat_core_search_all" in tool_names
    assert "wechat_core_contacts" in tool_names
    assert "wechat_core_events" in tool_names

    # Check legacy aliases
    assert "wechat_stats" in tool_names
    assert "wechat_chats" in tool_names
    assert "wechat_messages" in tool_names
    assert "wechat_search" in tool_names
    assert "wechat_contacts" in tool_names
    assert "wechat_sync" in tool_names


def test_tool_required_arguments_schema_compliance(test_reader: HistoryReader):
    """Verify tool parameter requirements and validation."""
    server = create_mcp_server(reader=test_reader)

    # Calling wechat_core_messages without required 'session'
    res = server.call_tool_sync("wechat_core_messages", {})
    assert res["schema"] == ERROR_SCHEMA
    assert res["error_type"] == "ValidationError"
    assert "Missing required argument: session" in res["message"]
    assert res["retry_unknown"] is False

    # Calling wechat_core_search without required 'query' or 'session'
    res_search = server.call_tool_sync("wechat_core_search", {"session": "test"})
    assert res_search["schema"] == ERROR_SCHEMA
    assert res_search["error_type"] == "ValidationError"
    assert "Missing required argument: query" in res_search["message"]

    # Calling unknown tool returns ToolNotFound
    res_unknown = server.call_tool_sync("wechat_unknown_tool_xyz", {})
    assert res_unknown["schema"] == ERROR_SCHEMA
    assert res_unknown["error_type"] == "ToolNotFound"


def test_safe_error_envelope_and_redaction():
    """Verify wechat.core.error.v1 envelope structure and sensitive data redaction."""
    err = safe_error(
        ValueError("Failed connecting to wxid_user123456789 at /Users/john_doe/secret.db"),
        error_type="ConnectionError",
    )
    assert err["schema"] == ERROR_SCHEMA
    assert err["error_type"] == "ConnectionError"
    assert err["code"] == "ConnectionError"
    assert err["retry_unknown"] is False
    assert "timestamp" in err

    # Redaction checks
    assert "wxid_user123456789" not in err["message"]
    assert "[REDACTED_WXID]" in err["message"]
    assert "/Users/john_doe" not in err["message"]
    assert "/Users/[USER]" in err["message"]


def test_legacy_aliases_parity_and_cursor_rejection(test_reader: HistoryReader):
    """Verify legacy aliases map to core equivalents and reject positive since_id."""
    server = create_mcp_server(reader=test_reader)

    # 1. Stats parity
    core_stats = server.call_tool_sync("wechat_core_stats")
    legacy_stats = server.call_tool_sync("wechat_stats")
    assert core_stats["chats"] == legacy_stats["chats"]
    assert core_stats["messages"] == legacy_stats["messages"]

    # 2. Chats / Sessions parity
    core_sessions = server.call_tool_sync("wechat_core_sessions")
    legacy_chats = server.call_tool_sync("wechat_chats")
    assert len(core_sessions["sessions"]) == len(legacy_chats["sessions"])

    # 3. Messages parity
    core_msgs = server.call_tool_sync("wechat_core_messages", {"session": "wxid_test1"})
    legacy_msgs = server.call_tool_sync("wechat_messages", {"username": "wxid_test1"})
    assert core_msgs["count"] == legacy_msgs["count"]
    assert core_msgs["messages"][0]["content"] == legacy_msgs["messages"][0]["content"]

    # 4. since_id > 0 rejection in wechat_messages
    rejected = server.call_tool_sync("wechat_messages", {"username": "wxid_test1", "since_id": 100})
    assert rejected["schema"] == ERROR_SCHEMA
    assert rejected["error_type"] == "UnsafeLegacyCursor"
    assert "not an incremental cursor" in rejected["message"]


def test_resource_push_event_subscription():
    """Test EventPush resource creation and read."""
    push = EventPush(groups=["group1@chatroom", "group2@chatroom"])
    uri = "wechat-core://events/group1%40chatroom"
    head = asyncio.run(push.read(uri))
    assert head["schema"] == "wechat.core.event-resource.v1"
    assert head["group"] == "group1@chatroom"
    assert head["state"] == "available"


def test_wechat_core_messages_cursor_pagination_advances_offset(tmp_path: Path):
    """Test cursor pagination advances offset across pages in wechat_core_messages."""
    db_storage = tmp_path / "page_storage"
    msg_dir = db_storage / "message"
    msg_dir.mkdir(parents=True)

    tname = md5_table("user_paged")
    with sqlite3.connect(msg_dir / "message_0.db") as db:
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
        for i in range(1, 6):
            db.execute(
                f'INSERT INTO "{tname}" VALUES({i}, {100 + i}, 1, {i}, 1, {1700000000 + i}, 2, "", "Message {i}", NULL, 0, 0);'
            )
        db.commit()

    reader = HistoryReader(db_storage)
    server = create_mcp_server(reader=reader)

    # Page 1: limit 2
    p1 = server.call_tool_sync("wechat_core_messages", {"session": "user_paged", "limit": 2})
    assert p1["count"] == 2
    assert p1["offset"] == 0
    assert p1["has_more"] is True
    assert p1["next_cursor"] == "cursor_2"
    assert [m["content"] for m in p1["messages"]] == ["Message 1", "Message 2"]

    # Page 2: with cursor="cursor_2"
    p2 = server.call_tool_sync("wechat_core_messages", {"session": "user_paged", "limit": 2, "cursor": p1["next_cursor"]})
    assert p2["count"] == 2
    assert p2["offset"] == 2
    assert p2["has_more"] is True
    assert p2["next_cursor"] == "cursor_4"
    assert [m["content"] for m in p2["messages"]] == ["Message 3", "Message 4"]

    # Page 3: with cursor="cursor_4"
    p3 = server.call_tool_sync("wechat_core_messages", {"session": "user_paged", "limit": 2, "cursor": p2["next_cursor"]})
    assert p3["count"] == 1
    assert p3["offset"] == 4
    assert p3["has_more"] is False
    assert p3["next_cursor"] is None
    assert [m["content"] for m in p3["messages"]] == ["Message 5"]

    # Mutual exclusion check: both cursor and offset > 0
    err = server.call_tool_sync("wechat_core_messages", {"session": "user_paged", "limit": 2, "cursor": "cursor_2", "offset": 2})
    assert err["schema"] == ERROR_SCHEMA
    assert "Use either a snapshot cursor or offset, not both" in err["message"]

    reader.shards.close()


def test_safe_error_details_recursive_sanitization():
    """Test recursive sanitization of details dict inside safe_error."""
    details = {
        "user": "wxid_alice123456789",
        "nested": {
            "path": "/Users/test_user/Library/Containers/com.tencent.xinWeChat",
            "targets": ["wxid_bob987654321", "plain_text"],
        },
        "count": 42,
    }
    err = safe_error("An error occurred", details=details)
    sanitized = err["details"]

    assert sanitized["user"] == "[REDACTED_WXID]"
    assert sanitized["nested"]["path"] == "/Users/[USER]/Library/Containers/com.tencent.xinWeChat"
    assert sanitized["nested"]["targets"][0] == "[REDACTED_WXID]"
    assert sanitized["nested"]["targets"][1] == "plain_text"
    assert sanitized["count"] == 42
