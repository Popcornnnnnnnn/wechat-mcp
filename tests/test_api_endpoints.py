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

"""Unit tests for FastAPI REST query endpoints on port 8300 using TestClient."""
from __future__ import annotations

from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient
import pytest

from wechat_mcp.api.server import create_api_app
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.shards import md5_table


@pytest.fixture
def api_test_client(tmp_path: Path) -> TestClient:
    """Create FastAPI TestClient against synthetic decrypted WeChat storage."""
    db_storage = tmp_path / "decrypted"
    msg_dir = db_storage / "message"
    contact_dir = db_storage / "contact"
    session_dir = db_storage / "session"
    msg_dir.mkdir(parents=True)
    contact_dir.mkdir(parents=True)
    session_dir.mkdir(parents=True)

    with sqlite3.connect(contact_dir / "contact.db") as db:
        db.execute("CREATE TABLE contact(id INT, username TEXT, alias TEXT, remark TEXT, nick_name TEXT);")
        db.execute("INSERT INTO contact VALUES(1, 'wxid_alice', 'alice_alias', 'Alice Boss', 'Alice');")
        db.execute("INSERT INTO contact VALUES(2, 'wxid_bob', 'bob_alias', '', 'Bob Developer');")
        db.commit()

    with sqlite3.connect(session_dir / "session.db") as db:
        db.execute("CREATE TABLE SessionTable(username TEXT, type INT, unread_count INT, summary TEXT, last_timestamp INT, last_msg_sender TEXT);")
        db.execute("INSERT INTO SessionTable VALUES('wxid_alice', 1, 0, 'Hi Alice', 1710000000, 'wxid_alice');")
        db.execute("INSERT INTO SessionTable VALUES('wxid_bob', 1, 0, 'Hi Bob', 1709000000, 'wxid_bob');")
        db.commit()

    tname_alice = md5_table("wxid_alice")
    with sqlite3.connect(msg_dir / "message_0.db") as db:
        db.execute("CREATE TABLE TimeStamp(timestamp INT);")
        db.execute("INSERT INTO TimeStamp VALUES(1708000000);")
        db.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER);")
        db.execute("INSERT INTO Name2Id(rowid, user_name, is_session) VALUES(1, 'wxid_alice', 0);")

        db.execute(f"""
            CREATE TABLE "{tname_alice}"(
                local_id INT, server_id INT, local_type INT, sort_seq INT,
                real_sender_id INT, create_time INT, status INT, source TEXT,
                message_content TEXT, compress_content TEXT,
                WCDB_CT_message_content INT, WCDB_CT_source INT
            );
        """)
        db.execute(f'INSERT INTO "{tname_alice}" VALUES(1, 101, 1, 1, 1, 1709999000, 2, "", "Message 1 for Alice", NULL, 0, 0);')
        db.execute(f'INSERT INTO "{tname_alice}" VALUES(2, 102, 1, 2, 1, 1710000000, 2, "", "Message 2 for Alice", NULL, 0, 0);')
        db.commit()

    reader = HistoryReader(db_storage)
    app = create_api_app(reader=reader)
    return TestClient(app)


def test_get_stats_route(api_test_client: TestClient):
    """Test GET /api/stats endpoint returns aggregate statistics."""
    res = api_test_client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["chats"] >= 2
    assert data["messages"] >= 2
    assert data["contacts"] >= 2
    assert "from" in data
    assert "to" in data


def test_get_chats_route_descending_order(api_test_client: TestClient):
    """Test GET /api/chats returns sessions sorted by last_timestamp descending."""
    res = api_test_client.get("/api/chats")
    assert res.status_code == 200
    chats = res.json()
    assert isinstance(chats, list)
    assert len(chats) >= 2
    timestamps = [c["last_timestamp"] for c in chats]
    assert timestamps == sorted(timestamps, reverse=True)


def test_get_chat_messages_pagination_and_since_id(api_test_client: TestClient):
    """Test GET /api/chats/{username}/messages with limit, offset, and since_id."""
    # 1. Page with limit=1
    res1 = api_test_client.get("/api/chats/wxid_alice/messages?limit=1&offset=0")
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["count"] == 1
    assert data1["total"] == 2
    assert data1["next_since_id"] == 101

    # 2. Incremental fetch using since_id
    res2 = api_test_client.get("/api/chats/wxid_alice/messages?since_id=101")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["count"] == 1
    assert data2["messages"][0]["server_id"] == 102
    assert data2["next_since_id"] == 102

    # 3. Nonexistent chat returns 200 with count=0
    res_none = api_test_client.get("/api/chats/nonexistent_chat/messages")
    assert res_none.status_code == 200
    data_none = res_none.json()
    assert data_none["count"] == 0
    assert data_none["messages"] == []


def test_get_contacts_search_filter(api_test_client: TestClient):
    """Test GET /api/contacts filtering by query substring."""
    res_all = api_test_client.get("/api/contacts")
    assert res_all.status_code == 200
    assert len(res_all.json()) >= 2

    res_alice = api_test_client.get("/api/contacts?q=Alice")
    assert res_alice.status_code == 200
    contacts = res_alice.json()
    assert len(contacts) == 1
    assert contacts[0]["username"] == "wxid_alice"


def test_get_search_query_and_sql_injection_defense(api_test_client: TestClient):
    """Test GET /api/search finds content and safely neutralizes SQL injection attempts."""
    # Valid match
    res_match = api_test_client.get("/api/search?q=Alice")
    assert res_match.status_code == 200
    results = res_match.json()
    assert len(results) >= 1
    assert any("Alice" in r["content"] for r in results)

    # Missing mandatory query 'q' returns 422
    res_missing = api_test_client.get("/api/search")
    assert res_missing.status_code == 422

    # SQL injection attempt returns 200 with empty array (not crashed or leaking)
    res_inject = api_test_client.get("/api/search?q=' OR 1=1 --")
    assert res_inject.status_code == 200
    assert res_inject.json() == []


def test_post_sync_trigger(api_test_client: TestClient):
    """Test POST /api/sync endpoint triggers sync and returns status."""
    res = api_test_client.post("/api/sync")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "sync_completed"
    assert "timestamp" in data


def test_cold_start_api_stats_on_empty_storage(tmp_path: Path):
    """Test GET /api/stats returns 200 with zeroes when initialized on empty storage directory."""
    empty_dir = tmp_path / "empty_api_dir"
    empty_dir.mkdir(parents=True)

    reader = HistoryReader(empty_dir)
    app = create_api_app(reader=reader)
    client = TestClient(app)

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["chats"] == 0
    assert data["messages"] == 0
    assert data["contacts"] == 0
    assert data["shard_count"] == 0
    assert data["from"] == 0
    assert data["to"] > 0

    reader.shards.close()
