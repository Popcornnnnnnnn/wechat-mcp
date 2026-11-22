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

"""Comprehensive unit tests for wechat_mcp.watcher.recall RecallArchive and FastMCP/CLI integration."""
import os
from pathlib import Path
import sqlite3
import time
from unittest.mock import MagicMock
from click.testing import CliRunner
import pytest

from wechat_mcp.cli import main
from wechat_mcp.mcp.server import create_mcp_server
from wechat_mcp.watcher.recall import RecallArchive, ReferenceRecallArchive


class MockHistoryReader:
    """Mock HistoryReader for controlled recall testing."""

    def __init__(self, messages=None, chats=None):
        self._messages = messages or {}
        self._chats = chats or []

    def get_messages(self, session: str, limit: int = 1000, offset: int = 0):
        msgs = self._messages.get(session, [])
        return {"messages": msgs[:limit], "count": len(msgs)}

    def list_chats(self, limit: int = 100, offset: int = 0):
        return {"chats": self._chats}


def test_recall_archive_initialization(tmp_path: Path):
    reader = MockHistoryReader()
    archive_file = tmp_path / "custom-archive.sqlite"
    archive = RecallArchive(tmp_path, archive_path=archive_file, reader=reader)

    assert archive.archive_path == archive_file.resolve()
    assert archive_file.exists()

    with sqlite3.connect(archive_file) as db:
        cur = db.execute("PRAGMA table_info(recalls);")
        cols = {row[1] for row in cur.fetchall()}
        assert "server_id" in cols
        assert "session" in cols
        assert "sender" in cols
        assert "content" in cols
        assert "recalled_at" in cols
        assert "source" in cols
        assert "media_path" in cols


def test_recall_signal_1_sysmsg_tip_preceding_match(tmp_path: Path):
    session = "test_chat@chatroom"
    msgs = [
        {"server_id": 101, "sender": "user1", "content": "Important secret message", "create_time": 1000, "type": 1},
        {"server_id": 102, "sender": "user1", "content": 'user1 撤回了一条消息', "create_time": 1005, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 1
    assert detected[0]["server_id"] == 101
    assert detected[0]["source"] == "tip"
    assert detected[0]["content"] == "Important secret message"

    stats = archive.get_recall_stats()
    assert stats["total"] == 1
    assert stats["tip"] == 1
    assert stats["diff"] == 0


def test_recall_signal_1_xml_newmsgid_match(tmp_path: Path):
    session = "group@chatroom"
    xml_content = (
        '<sysmsg type="revokemsg">'
        '<revokemsg>'
        '<session>group@chatroom</session>'
        '<newmsgid>205</newmsgid>'
        '<replacemsg><![CDATA[User revoked a message]]></replacemsg>'
        '</revokemsg>'
        '</sysmsg>'
    )
    msgs = [
        {"server_id": 204, "sender": "user1", "content": "Keep this", "create_time": 100, "type": 1},
        {"server_id": 205, "sender": "user2", "content": "Target revoke msg", "create_time": 102, "type": 1},
        {"server_id": 206, "sender": "sys", "content": xml_content, "create_time": 110, "type": 10002},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 1
    assert detected[0]["server_id"] == 205
    assert detected[0]["source"] == "tip"
    assert detected[0]["content"] == "Target revoke msg"


def test_recall_signal_1_malformed_xml_regex_fallback(tmp_path: Path):
    session = "group@chatroom"
    malformed = '<sysmsg type="revokemsg"><session>group@chatroom</session><newmsgid>305</newmsgid><unclosed_tag>'
    msgs = [
        {"server_id": 305, "sender": "user2", "content": "Recoverable via regex", "create_time": 200, "type": 1},
        {"server_id": 306, "sender": "sys", "content": malformed, "create_time": 210, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 1
    assert detected[0]["server_id"] == 305
    assert detected[0]["content"] == "Recoverable via regex"


def test_recall_signal_2_vanished_diff(tmp_path: Path):
    session = "direct_chat"
    initial_msgs = [
        {"server_id": 501, "sender": "alice", "content": "Disappearing message", "create_time": 500, "type": 1},
        {"server_id": 502, "sender": "bob", "content": "Persistent message", "create_time": 501, "type": 1},
    ]
    reader = MockHistoryReader(messages={session: list(initial_msgs)})
    archive = RecallArchive(tmp_path, reader=reader)

    # Pre-index
    archive.index_current_messages(session)

    # Vanish message 501 from current database
    reader._messages[session] = [
        {"server_id": 502, "sender": "bob", "content": "Persistent message", "create_time": 501, "type": 1}
    ]

    detected = archive.scan(session)
    assert len(detected) == 1
    assert detected[0]["server_id"] == 501
    assert detected[0]["source"] == "diff"
    assert detected[0]["content"] == "Disappearing message"

    stats = archive.get_recall_stats()
    assert stats["diff"] == 1


def test_recall_table_cleared_safety_guard(tmp_path: Path):
    session = "wiped_chat"
    initial_msgs = [
        {"server_id": 601, "sender": "user", "content": "msg 1", "create_time": 1, "type": 1},
        {"server_id": 602, "sender": "user", "content": "msg 2", "create_time": 2, "type": 1},
        {"server_id": 603, "sender": "user", "content": "msg 3", "create_time": 3, "type": 1},
    ]
    reader = MockHistoryReader(messages={session: initial_msgs})
    archive = RecallArchive(tmp_path, reader=reader)
    archive.index_current_messages(session)

    # Entire database cleared
    reader._messages[session] = []

    detected = archive.scan(session)
    assert len(detected) == 0  # Guard prevents mass recall false positives
    stats = archive.get_recall_stats()
    assert stats["total"] == 0


def test_recall_idempotent_scanning(tmp_path: Path):
    session = "idempotent_chat"
    msgs = [
        {"server_id": 701, "sender": "user1", "content": "Msg to revoke", "create_time": 100, "type": 1},
        {"server_id": 702, "sender": "user1", "content": "user1 撤回了一条消息", "create_time": 105, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected1 = archive.scan(session)
    assert len(detected1) == 1

    detected2 = archive.scan(session)
    assert len(detected2) == 0

    stats = archive.get_recall_stats()
    assert stats["total"] == 1


def test_recall_corrupted_zstd_preserved(tmp_path: Path):
    session = "corrupt_chat"
    msgs = [
        {"server_id": 801, "sender": "user", "content": "[Decompression Failed]", "create_time": 10, "type": 1},
    ]
    reader = MockHistoryReader(messages={session: list(msgs)})
    archive = RecallArchive(tmp_path, reader=reader)
    archive.index_current_messages(session)

    # Message vanishes
    reader._messages[session] = []
    # But wait: if length is 0, table cleared guard triggers. Add another message so len > 0.
    reader._messages[session] = [
        {"server_id": 802, "sender": "other", "content": "new msg", "create_time": 15, "type": 1}
    ]

    detected = archive.scan(session)
    assert len(detected) == 1
    assert detected[0]["content"] == "[Decompression Failed]"


def test_recall_readonly_database_error(tmp_path: Path):
    session = "readonly_chat"
    archive_file = tmp_path / "readonly.sqlite"
    msgs = [
        {"server_id": 901, "sender": "u", "content": "hello", "create_time": 1, "type": 1},
        {"server_id": 902, "sender": "u", "content": "撤回", "create_time": 2, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, archive_path=archive_file, reader=reader)

    # Make archive readonly
    os.chmod(archive_file, 0o444)

    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            archive.scan(session)
    finally:
        os.chmod(archive_file, 0o644)


def test_fastmcp_recall_tools_integration(tmp_path: Path):
    session = "mcp_test@chatroom"
    msgs = [
        {"server_id": 1001, "sender": "alice", "content": "MCP Secret Revealed", "create_time": 10, "type": 1},
        {"server_id": 1002, "sender": "alice", "content": "alice 撤回了一条消息", "create_time": 12, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    server = create_mcp_server(reader=reader, recall_archive=archive)

    # Scan and detect
    archive.scan(session)

    # Call wechat_core_recalls
    res = server.call_tool_sync("wechat_core_recalls", {"session": session, "refresh": False})
    assert res["schema"] == "wechat.core.v1"
    assert res["total"] == 1
    assert res["recalls"][0]["content"] == "MCP Secret Revealed"

    # Call wechat_core_recall_stats
    stats_res = server.call_tool_sync("wechat_core_recall_stats", {})
    assert stats_res["schema"] == "wechat.core.v1"
    assert stats_res["total"] == 1
    assert stats_res["tip"] == 1


def test_cli_recall_subcommand_once(tmp_path: Path):
    runner = CliRunner()
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()

    result = runner.invoke(main, ["recall", "--once", "--archive-dir", str(archive_dir), "--db-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "RecallArchive initialized" in result.output
    assert "Scan complete" in result.output


def test_recall_plain_tip_idempotency_multi_message(tmp_path: Path):
    """Verify repeated scans on a multi-message session do not cascade backward."""
    session = "cascading_test"
    msgs = [
        {"server_id": 1, "sender": "user1", "content": "msg 1", "create_time": 1, "type": 1},
        {"server_id": 2, "sender": "user1", "content": "msg 2", "create_time": 2, "type": 1},
        {"server_id": 3, "sender": "user1", "content": "msg 3", "create_time": 3, "type": 1},
        {"server_id": 4, "sender": "user1", "content": "user1 撤回了一条消息", "create_time": 4, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: list(msgs)})
    archive = RecallArchive(tmp_path, reader=reader)

    # First scan should detect only msg 3
    scan1 = archive.scan(session)
    assert len(scan1) == 1
    assert scan1[0]["server_id"] == 3

    # Subsequent scans must return 0 new recalls (no backward cascading to msg 2 or msg 1)
    scan2 = archive.scan(session)
    assert len(scan2) == 0

    scan3 = archive.scan(session)
    assert len(scan3) == 0

    stats = archive.get_recall_stats()
    assert stats["total"] == 1
    assert stats["tip"] == 1

    # FastMCP wechat_core_recalls with refresh=True should also remain stable
    server = create_mcp_server(reader=reader, recall_archive=archive)
    mcp_res1 = server.call_tool_sync("wechat_core_recalls", {"session": session, "refresh": True})
    assert mcp_res1["total"] == 1
    mcp_res2 = server.call_tool_sync("wechat_core_recalls", {"session": session, "refresh": True})
    assert mcp_res2["total"] == 1


def test_recall_non_revoke_system_message_ignored(tmp_path: Path):
    """Verify normal Type 10000 system messages do NOT trigger recall."""
    session = "group@chatroom"
    msgs = [
        {"server_id": 201, "sender": "alice", "content": "Welcome Alice!", "create_time": 100, "type": 1},
        {"server_id": 202, "sender": "sys", "content": "Bob joined the group chat", "create_time": 105, "type": 10000},
        {"server_id": 203, "sender": "alice", "content": "Nice to meet you", "create_time": 110, "type": 1},
        {"server_id": 204, "sender": "sys", "content": "Charlie invited Dave to the group chat", "create_time": 115, "type": 10000},
        {"server_id": 205, "sender": "sys", "content": "Admin changed group name to Team Chat", "create_time": 120, "type": 10000},
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 0
    stats = archive.get_recall_stats()
    assert stats["total"] == 0


def test_recall_xml_non_revoke_system_messages_ignored(tmp_path: Path):
    """Verify various WeChat XML system messages (<sysmsg type="...">) do NOT trigger recall."""
    session = "group@chatroom"
    xml_sysmsgs = [
        '<sysmsg type="delchatroommember"><delchatroommember><member>m</member></delchatroommember></sysmsg>',
        '<sysmsg type="pat"><pat><from>alice</from><to>bob</to></pat></sysmsg>',
        '<sysmsg type="luckymoney"><luckymoney><text>Red packet</text></luckymoney></sysmsg>',
        '<sysmsg type="roomtoolflag"><roomtoolflag><flag>1</flag></roomtoolflag></sysmsg>',
        '<sysmsg type="todo"><todo><action>create</action></todo></sysmsg>',
        '<sysmsg type="functionmsg"><functionmsg><type>pay</type></functionmsg></sysmsg>',
        '<sysmsg type="trackroomtraffic"><track>traffic</track></sysmsg>',
        '<sysmsg type="solitaire"><solitaire>data</solitaire></sysmsg>',
        '<sysmsg type="openim"><openim>contact</openim></sysmsg>',
    ]
    msgs = []
    sid = 1
    t = 100
    for xml in xml_sysmsgs:
        # Normal chat message
        msgs.append({
            "server_id": sid,
            "sender": "alice",
            "content": f"Normal user message {sid}",
            "create_time": t,
            "type": 1,
        })
        sid += 1
        t += 2
        # XML system message within 300s
        msgs.append({
            "server_id": sid,
            "sender": "sys",
            "content": xml,
            "create_time": t,
            "type": 10000,
        })
        sid += 1
        t += 2

    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 0, f"False recalls detected: {detected}"
    stats = archive.get_recall_stats()
    assert stats["total"] == 0


def test_recall_malformed_xml_non_revoke_ignored(tmp_path: Path):
    """Verify malformed non-revoke XML does not trigger fallback recall."""
    session = "group@chatroom"
    msgs = [
        {"server_id": 1, "sender": "alice", "content": "Hello", "create_time": 100, "type": 1},
        {
            "server_id": 2,
            "sender": "sys",
            "content": '<sysmsg type="delchatroommember"><unclosed_tag>',
            "create_time": 105,
            "type": 10000,
        },
    ]
    reader = MockHistoryReader(messages={session: msgs})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 0, f"False recalls detected: {detected}"
    assert archive.get_recall_stats()["total"] == 0


def test_recall_sliding_window_zero_timestamp_message(tmp_path: Path):
    """Verify sliding pagination window does not collapse diff protection when create_time==0."""
    session = "large_chat"
    initial_msgs = [
        {"server_id": i, "sender": "user", "content": f"msg {i}", "create_time": i, "type": 1}
        for i in range(1, 1001)
    ]
    reader = MockHistoryReader(messages={session: list(initial_msgs)})
    archive = RecallArchive(tmp_path, reader=reader)
    archive.index_current_messages(session)

    # 10 new messages arrive, pushing messages 1-10 out of window
    # Additionally inject a message with create_time=0
    new_msgs = [
        {"server_id": i, "sender": "user", "content": f"msg {i}", "create_time": i, "type": 1}
        for i in range(11, 1010)
    ]
    new_msgs.append({
        "server_id": 9999,
        "sender": "user",
        "content": "zero timestamp message",
        "create_time": 0,
        "type": 1,
    })
    reader._messages[session] = new_msgs

    detected = archive.scan(session)
    assert len(detected) == 0, f"False recalls detected: {detected}"
    stats = archive.get_recall_stats()
    assert stats["total"] == 0


def test_recall_sliding_window_pagination_no_false_positive(tmp_path: Path):
    """Verify sliding pagination window (1000 messages) does not falsely trigger diff recall."""
    session = "large_chat"
    initial_msgs = [
        {"server_id": i, "sender": "user", "content": f"msg {i}", "create_time": i, "type": 1}
        for i in range(1, 1001)
    ]
    reader = MockHistoryReader(messages={session: list(initial_msgs)})
    archive = RecallArchive(tmp_path, reader=reader)
    archive.index_current_messages(session)

    # 10 new messages arrive, pushing messages 1-10 out of the 1000-message fetch window
    new_msgs = [
        {"server_id": i, "sender": "user", "content": f"msg {i}", "create_time": i, "type": 1}
        for i in range(11, 1011)
    ]
    reader._messages[session] = new_msgs

    detected = archive.scan(session)
    assert len(detected) == 0
    stats = archive.get_recall_stats()
    assert stats["total"] == 0


def test_fastmcp_wechat_core_events_with_journal(tmp_path: Path):
    """Verify wechat_core_events drains events from EventJournal."""
    from wechat_mcp.watcher.journal import EventJournal

    journal_file = tmp_path / "journal.sqlite"
    journal = EventJournal(journal_file)
    journal.append(event_type="msg", chatroom_id="room1@chatroom", payload={"text": "hello 1"})
    journal.append(event_type="msg", chatroom_id="room1@chatroom", payload={"text": "hello 2"})
    journal.append(event_type="msg", chatroom_id="other@chatroom", payload={"text": "other room"})

    reader = MockHistoryReader()
    server = create_mcp_server(reader=reader, journal=journal)

    # Poll events for room1@chatroom
    res = server.call_tool_sync("wechat_core_events", {"group": "room1@chatroom"})
    assert res["schema"] == "wechat.core.events.v1"
    assert res["group"] == "room1@chatroom"
    assert len(res["events"]) == 2
    assert res["events"][0]["seq"] == 1
    assert res["events"][1]["seq"] == 2
    assert res["next_cursor"] == "2"
    assert res["has_more"] is False

    # Poll with cursor=1
    res_c1 = server.call_tool_sync("wechat_core_events", {"group": "room1@chatroom", "cursor": "1"})
    assert len(res_c1["events"]) == 1
    assert res_c1["events"][0]["seq"] == 2


def test_recall_user_text_chat_mentioning_recall_ignored(tmp_path: Path):
    """Regression test: User chat messages (type=1) mentioning '撤回' or 'recalled a message' do not trigger false recall."""
    session = "discussion@chatroom"
    messages = [
        {"server_id": 101, "sender": "alice", "content": "Meeting at 3pm tomorrow", "create_time": 1000, "type": 1},
        {"server_id": 102, "sender": "bob", "content": "你刚才撤回了什么？", "create_time": 1005, "type": 1},
        {"server_id": 103, "sender": "charlie", "content": "我没撤回啊，网络不好", "create_time": 1010, "type": 1},
        {"server_id": 104, "sender": "david", "content": "Why did you recall a message?", "create_time": 1015, "type": 1},
        {"server_id": 105, "sender": "eve", "content": "撤回测试消息", "create_time": 1020, "type": 1},
    ]

    reader = MockHistoryReader(messages={session: messages})
    archive = RecallArchive(tmp_path, reader=reader)

    detected = archive.scan(session)
    assert len(detected) == 0, f"False recalls detected: {detected}"
    assert archive.get_recall_stats()["total"] == 0

    # Genuine revoke tip (type=10000) should still be correctly detected
    genuine_tip = {"server_id": 106, "sender": "sys", "content": "eve 撤回了一条消息", "create_time": 1025, "type": 10000}
    reader._messages[session].append(genuine_tip)

    detected_genuine = archive.scan(session)
    assert len(detected_genuine) == 1
    assert detected_genuine[0]["server_id"] == 105  # The target was 105 (eve's message), not the tip itself
    assert detected_genuine[0]["source"] == "tip"
    assert detected_genuine[0]["content"] == "撤回测试消息"


