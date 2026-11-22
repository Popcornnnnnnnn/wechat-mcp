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

"""Watcher module for real-time macOS WeChat database monitoring and event journaling."""
from wechat_mcp.watcher.journal import EventJournal, ReferenceEventJournal
from wechat_mcp.watcher.kqueue import (
    KqueueWatcher,
    ReferenceKqueueWatcher,
    VnodeFlags,
    VnodeWatch,
    WatcherEvent,
)
from wechat_mcp.watcher.recall import RecallArchive, ReferenceRecallArchive

__all__ = [
    "VnodeWatch",
    "KqueueWatcher",
    "ReferenceKqueueWatcher",
    "VnodeFlags",
    "WatcherEvent",
    "EventJournal",
    "ReferenceEventJournal",
    "RecallArchive",
    "ReferenceRecallArchive",
]
