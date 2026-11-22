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

"""Comprehensive unit tests for wechat_mcp.watcher kqueue monitor and EventJournal."""
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import List
import pytest

from wechat_mcp.watcher.journal import EventJournal, ReferenceEventJournal
from wechat_mcp.watcher.kqueue import (
    KqueueWatcher,
    ReferenceKqueueWatcher,
    VnodeFlags,
    VnodeWatch,
    WatcherEvent,
)


def test_vnode_flags_values():
    assert VnodeFlags.NOTE_DELETE == 0x01
    assert VnodeFlags.NOTE_WRITE == 0x02
    assert VnodeFlags.NOTE_EXTEND == 0x04
    assert VnodeFlags.NOTE_ATTRIB == 0x08
    assert VnodeFlags.NOTE_LINK == 0x10
    assert VnodeFlags.NOTE_RENAME == 0x20
    assert VnodeFlags.NOTE_REVOKE == 0x40
    assert VnodeFlags.NOTE_TRUNCATE == 0x80

    combined = VnodeFlags.NOTE_WRITE | VnodeFlags.NOTE_EXTEND
    assert combined & VnodeFlags.NOTE_WRITE
    assert combined & VnodeFlags.NOTE_EXTEND
    assert not (combined & VnodeFlags.NOTE_DELETE)


def test_kqueue_watcher_file_watch_and_emit(tmp_path: Path):
    watcher = VnodeWatch(tmp_path)
    test_file = tmp_path / "message_0.db"
    test_file.write_bytes(b"initial data")

    events_received: List[WatcherEvent] = []
    watcher.subscribe(lambda ev: events_received.append(ev))

    watcher.watch_file(test_file, VnodeFlags.NOTE_WRITE)
    ev = watcher.emit_event(test_file, VnodeFlags.NOTE_WRITE)

    assert ev is not None
    assert ev.path == test_file.resolve()
    assert ev.flags & VnodeFlags.NOTE_WRITE
    assert len(events_received) == 1
    assert events_received[0].seq == 1
    watcher.close()


def test_kqueue_watcher_temporal_debouncing(tmp_path: Path):
    watcher = VnodeWatch(tmp_path, debounce_interval_ms=50.0)
    test_file = tmp_path / "message_0.db-wal"
    test_file.write_bytes(b"wal1")

    events_received: List[WatcherEvent] = []
    watcher.subscribe(lambda ev: events_received.append(ev))
    watcher.watch_file(test_file)

    # First event emitted
    ev1 = watcher.emit_event(test_file, VnodeFlags.NOTE_WRITE)
    assert ev1 is not None

    # Immediate subsequent rapid events within 10ms should be debounced / coalesced
    coalesced_count = 0
    for _ in range(10):
        ev = watcher.emit_event(test_file, VnodeFlags.NOTE_WRITE)
        if ev is None:
            coalesced_count += 1

    assert coalesced_count > 0
    assert len(events_received) == 1

    # After debounce interval elapses, next write is emitted
    time.sleep(0.06)
    ev2 = watcher.emit_event(test_file, VnodeFlags.NOTE_WRITE)
    assert ev2 is not None
    assert len(events_received) == 2
    watcher.close()


def test_kqueue_watcher_file_deletion(tmp_path: Path):
    watcher = VnodeWatch(tmp_path)
    test_file = tmp_path / "contact.db"
    test_file.write_bytes(b"contacts")

    events_received: List[WatcherEvent] = []
    watcher.subscribe(lambda ev: events_received.append(ev))
    watcher.watch_file(test_file)

    # Delete the file and emit event
    test_file.unlink()
    ev = watcher.emit_event(test_file, VnodeFlags.NOTE_WRITE)
    assert ev is not None
    assert ev.flags & VnodeFlags.NOTE_DELETE
    watcher.close()


def test_kqueue_watcher_max_watches_limit(tmp_path: Path):
    watcher = VnodeWatch(tmp_path, max_watches=2)
    f1 = tmp_path / "f1.db"
    f2 = tmp_path / "f2.db"
    f3 = tmp_path / "f3.db"
    f1.touch()
    f2.touch()
    f3.touch()

    watcher.watch_file(f1)
    watcher.watch_file(f2)

    with pytest.raises(OSError) as exc_info:
        watcher.watch_file(f3)
    assert exc_info.value.errno == 24 or "Too many open files" in str(exc_info.value)
    watcher.close()


def test_kqueue_watcher_unwatch(tmp_path: Path):
    watcher = VnodeWatch(tmp_path)
    f1 = tmp_path / "f1.db"
    f1.touch()

    watcher.watch_file(f1)
    assert f1.resolve() in watcher.watches

    watcher.unwatch_file(f1)
    assert f1.resolve() not in watcher.watches
    watcher.close()


def test_vnode_watch_context_manager(tmp_path: Path):
    with VnodeWatch(tmp_path) as watcher:
        f = tmp_path / "test.db"
        f.touch()
        watcher.watch_file(f)
        assert f.resolve() in watcher.watches


def test_event_journal_monotonic_seq(tmp_path: Path):
    db_path = tmp_path / "journal.sqlite"
    journal = EventJournal(db_path)

    seq1 = journal.append("new_msg", "room1@chatroom", {"text": "hello"}, sender_id="wxid_1")
    seq2 = journal.append("new_msg", "room1@chatroom", {"text": "world"}, sender_id="wxid_2")
    seq3 = journal.append("revoke", "room1@chatroom", {"tip": "revoked"}, sender_id="wxid_1")

    assert seq1 == 1
    assert seq2 == 2
    assert seq3 == 3


def test_event_journal_append_batch(tmp_path: Path):
    db_path = tmp_path / "journal.sqlite"
    journal = EventJournal(db_path)

    events = [
        {"event_type": "msg", "chatroom_id": "r1@chatroom", "payload": {"i": 1}, "sender_id": "u1"},
        {"event_type": "msg", "chatroom_id": "r1@chatroom", "payload": {"i": 2}, "sender_id": "u2"},
        {"event_type": "msg", "chatroom_id": "r2@chatroom", "payload": {"i": 3}, "sender_id": "u3"},
    ]

    seqs = journal.append_batch(events)
    assert seqs == [1, 2, 3]


def test_event_journal_drain_and_filter(tmp_path: Path):
    db_path = tmp_path / "journal.sqlite"
    journal = EventJournal(db_path)

    journal.append("msg", "room_a@chatroom", {"content": "msg 1"}, sender_id="u1")
    journal.append("msg", "room_b@chatroom", {"content": "msg 2"}, sender_id="u2")
    journal.append("msg", "room_a@chatroom", {"content": "msg 3"}, sender_id="u3")

    # Drain all from beginning
    all_events = journal.drain(since_seq=0)
    assert len(all_events) == 3

    # Drain since seq 1
    since_1 = journal.drain(since_seq=1)
    assert len(since_1) == 2
    assert since_1[0]["seq"] == 2
    assert since_1[1]["seq"] == 3

    # Drain by chatroom filter
    room_a = journal.drain(chatroom_id="room_a@chatroom")
    assert len(room_a) == 2
    assert all(e["chatroom_id"] == "room_a@chatroom" for e in room_a)

    # Negative sequence clamped to 0
    neg = journal.drain(since_seq=-999)
    assert len(neg) == 3


def test_event_journal_head_and_groups(tmp_path: Path):
    db_path = tmp_path / "journal.sqlite"
    journal = EventJournal(db_path)

    head_empty = journal.head()
    assert head_empty["head_cursor"] == "0"
    assert head_empty["change_token"] == "token_0"

    journal.append("msg", "room_x@chatroom", {"data": 1})
    journal.append("msg", "room_y@chatroom", {"data": 2})

    head_all = journal.head()
    assert head_all["head_cursor"] == "2"
    assert head_all["change_token"] == "token_2"

    head_x = journal.head("room_x@chatroom")
    assert head_x["head_cursor"] == "1"

    groups = sorted(journal.groups)
    assert groups == ["room_x@chatroom", "room_y@chatroom"]


def test_event_journal_locked_database_retry(tmp_path: Path):
    db_path = tmp_path / "journal_locked.sqlite"
    journal = EventJournal(db_path, max_retries=4)

    attempts = 0

    def flaky_conn():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise sqlite3.OperationalError("database is locked")
        return sqlite3.connect(db_path)

    journal._get_connection = flaky_conn
    seq = journal.append("msg", "test@chatroom", {"retry": True})
    assert seq == 1
    assert attempts == 3


def test_event_journal_schema_migration(tmp_path: Path):
    db_path = tmp_path / "old_journal.sqlite"
    # Create older schema without metadata, sender_id, msg_id
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE event_journal (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                chatroom_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        conn.commit()

    journal = EventJournal(db_path)
    journal.migrate_schema()

    with sqlite3.connect(db_path) as conn:
        cur = conn.execute("PRAGMA table_info(event_journal);")
        cols = {row[1] for row in cur.fetchall()}
        assert "metadata" in cols
        assert "sender_id" in cols
        assert "msg_id" in cols


def test_kqueue_watcher_wal_append_debouncing_coalesced(tmp_path: Path):
    """Regression test: WAL append bursts (NOTE_WRITE | NOTE_EXTEND) within debounce window are coalesced."""
    wal_file = tmp_path / "message_0.db-wal"
    wal_file.write_bytes(b"initial\n")

    watcher = VnodeWatch(tmp_path, auto_rescan=True, debounce_interval_ms=100.0)
    events: List[WatcherEvent] = []
    watcher.subscribe(lambda ev: events.append(ev))

    # Test direct flag coalescing: NOTE_WRITE | NOTE_EXTEND
    ev1 = watcher.emit_event(wal_file, VnodeFlags.NOTE_WRITE | VnodeFlags.NOTE_EXTEND)
    assert ev1 is not None
    assert len(events) == 1

    # Rapid bursts within debounce interval must be coalesced
    coalesced_count = 0
    for _ in range(10):
        ev = watcher.emit_event(wal_file, VnodeFlags.NOTE_WRITE | VnodeFlags.NOTE_EXTEND)
        if ev is None:
            coalesced_count += 1
    assert coalesced_count == 10
    assert len(events) == 1

    # Real file write burst test if kqueue is available
    if watcher._queue is not None:
        events.clear()
        time.sleep(0.12)  # Wait for previous window to expire
        for i in range(10):
            with open(wal_file, "ab") as f:
                f.write(f"data {i}\n".encode())
            watcher.wait(timeout=0.01)
        assert len(events) == 1, f"Expected 1 coalesced event, got {len(events)}"

    watcher.close()


def test_kqueue_watcher_truncation_detection(tmp_path: Path):
    """Regression test: WAL truncation (NOTE_TRUNCATE | NOTE_ATTRIB) triggers event detection in wait()."""
    wal_file = tmp_path / "message_0.db-wal"
    wal_file.write_bytes(b"initial content before checkpoint\n")

    watcher = VnodeWatch(tmp_path, auto_rescan=True)
    events: List[WatcherEvent] = []
    watcher.subscribe(lambda ev: events.append(ev))

    # Verify direct emission of truncation flags
    ev_trunc = watcher.emit_event(wal_file, VnodeFlags.NOTE_TRUNCATE | VnodeFlags.NOTE_ATTRIB)
    assert ev_trunc is not None
    assert ev_trunc.flags & VnodeFlags.NOTE_TRUNCATE
    assert ev_trunc.flags & VnodeFlags.NOTE_ATTRIB

    # Real OS kevent truncation detection if kqueue is available
    if watcher._queue is not None:
        def do_truncate():
            time.sleep(0.05)
            with open(wal_file, "wb") as f:
                f.truncate(0)

        t = threading.Thread(target=do_truncate)
        t.start()
        changed = watcher.wait(timeout=1.0)
        t.join()
        assert changed is True, "VnodeWatch.wait() failed to detect file truncation"

    watcher.close()

