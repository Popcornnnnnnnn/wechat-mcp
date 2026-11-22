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

"""kqueue vnode file system monitor for macOS WeChat databases."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
import errno
import logging
import os
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

logger = logging.getLogger("wechat_mcp.watcher.kqueue")

try:
    import select
    HAS_KQUEUE = hasattr(select, "kqueue")
except ImportError:
    HAS_KQUEUE = False


class VnodeFlags(IntFlag):
    """Vnode event flags modeled after BSD / macOS sys/event.h EVFILT_VNODE."""
    NOTE_DELETE = 0x00000001
    NOTE_WRITE = 0x00000002
    NOTE_EXTEND = 0x00000004
    NOTE_ATTRIB = 0x00000008
    NOTE_LINK = 0x00000010
    NOTE_RENAME = 0x00000020
    NOTE_REVOKE = 0x00000040
    NOTE_TRUNCATE = 0x00000080


@dataclass
class WatcherEvent:
    """Represents a monitored file-system change event."""
    path: Path
    flags: VnodeFlags
    timestamp: float
    seq: int = 0


class VnodeWatch:
    """
    kqueue vnode file system monitor implementing PROJECT.md §F6 contract.
    
    Features:
    - Target registration with descriptor limit enforcement (simulates EMFILE).
    - Event loop subscription mechanism with callback dispatch.
    - Configurable temporal debouncing and coalescing of rapid writes.
    - Automatic reconnection / re-arming after file rotation/truncation.
    - Directory scanning for candidate WeChat DB & WAL files.
    """

    DB_PATTERNS = (
        "message_[0-9]*.db",
        "message_[0-9]*.db-wal",
        "contact.db",
        "contact.db-wal",
        "session.db",
        "session.db-wal",
        "favorite.db",
        "favorite.db-wal",
        "sns.db",
        "sns.db-wal",
        "general.db",
        "general.db-wal",
    )

    def __init__(
        self,
        base_dir: Optional[Union[str, Path]] = None,
        debounce_interval_ms: float = 50.0,
        max_watches: int = 1024,
        auto_rescan: bool = False,
    ):
        self.base_dir = Path(base_dir).resolve() if base_dir else None
        self.path = self.base_dir  # Legacy compatibility alias
        self.debounce_interval_ms = float(debounce_interval_ms)
        self.max_watches = int(max_watches)
        self.watches: Dict[Path, VnodeFlags] = {}
        self.handles: Dict[Path, int] = {}  # Path -> OS file descriptor
        self.subscribers: List[Callable[[WatcherEvent], None]] = []
        self._last_event_time: Dict[Path, float] = {}
        self._event_seq = 0
        self._queue = None

        if HAS_KQUEUE:
            try:
                self._queue = select.kqueue()
            except Exception as e:
                logger.debug("kqueue initialization skipped: %s", e)
                self._queue = None
        self.queue = self._queue  # Legacy attribute access

        if self.base_dir and auto_rescan and self.base_dir.is_dir():
            try:
                self.rescan()
            except BaseException:
                self.close()
                raise

    def watch_file(
        self,
        path: Union[str, Path],
        flags: VnodeFlags = (
            VnodeFlags.NOTE_WRITE
            | VnodeFlags.NOTE_EXTEND
            | VnodeFlags.NOTE_TRUNCATE
            | VnodeFlags.NOTE_ATTRIB
        ),
    ) -> None:
        """Register a file path for vnode monitoring."""
        p = Path(path).resolve()
        if p not in self.watches and len(self.watches) >= self.max_watches:
            raise OSError(errno.EMFILE, "Too many open files")
        self.watches[p] = flags

        # If real kqueue is available and file exists on disk, arm OS descriptor
        if self._queue is not None and p.exists() and p not in self.handles:
            self._arm_os_watch(p, flags)

    def add_watch(
        self,
        path: Union[str, Path],
        flags: VnodeFlags = (
            VnodeFlags.NOTE_WRITE
            | VnodeFlags.NOTE_EXTEND
            | VnodeFlags.NOTE_TRUNCATE
            | VnodeFlags.NOTE_ATTRIB
        ),
    ) -> None:
        """Alias for watch_file."""
        self.watch_file(path, flags)

    def unwatch_file(self, path: Union[str, Path]) -> None:
        """Deregister a monitored file path."""
        p = Path(path).resolve()
        self.watches.pop(p, None)
        self._last_event_time.pop(p, None)
        self._disarm_os_watch(p)

    def subscribe(self, callback: Callable[[WatcherEvent], None]) -> None:
        """Register an event listener callback."""
        self.subscribers.append(callback)

    def emit_event(
        self,
        path: Union[str, Path],
        flags: VnodeFlags,
    ) -> Optional[WatcherEvent]:
        """
        Process a file event, apply debouncing/coalescing, and dispatch to subscribers.
        Returns the generated WatcherEvent or None if coalesced.
        """
        p = Path(path).resolve()
        now = time.time()
        last_t = self._last_event_time.get(p, 0.0)

        # Handle rapid write coalescing within debounce window
        if (
            (now - last_t) * 1000.0 < self.debounce_interval_ms
            and bool(flags & VnodeFlags.NOTE_WRITE)
            and not bool(flags & (VnodeFlags.NOTE_DELETE | VnodeFlags.NOTE_RENAME))
        ):
            return None

        # Check for file deletion
        if not p.exists() and not (flags & VnodeFlags.NOTE_DELETE):
            flags = flags | VnodeFlags.NOTE_DELETE

        self._last_event_time[p] = now
        self._event_seq += 1
        event = WatcherEvent(path=p, flags=flags, timestamp=now, seq=self._event_seq)

        for callback in list(self.subscribers):
            try:
                callback(event)
            except Exception as e:
                logger.warning("Error in watcher callback: %s", e)

        return event

    def rescan(self) -> None:
        """Scan base directory for candidate DB/WAL files and arm watches."""
        if not self.base_dir or not self.base_dir.is_dir():
            return

        candidates: Set[Path] = {self.base_dir}
        for pattern in self.DB_PATTERNS:
            try:
                candidates.update(self.base_dir.glob(pattern))
            except Exception:
                pass

        for p in candidates:
            resolved = p.resolve()
            if resolved not in self.handles:
                self.watch_file(
                    resolved,
                    VnodeFlags.NOTE_WRITE
                    | VnodeFlags.NOTE_EXTEND
                    | VnodeFlags.NOTE_RENAME
                    | VnodeFlags.NOTE_DELETE
                    | VnodeFlags.NOTE_TRUNCATE
                    | VnodeFlags.NOTE_ATTRIB,
                )

    def wait(self, timeout: float = 30.0) -> bool:
        """
        Poll kqueue for file system changes.
        Returns True if monitored database files changed, False on timeout.
        """
        if self._queue is None:
            return False

        changed = False
        try:
            events = self._queue.control(None, 64, timeout)
        except OSError:
            return False

        for e in events:
            path = next((p for p, fd in self.handles.items() if fd == e.ident), None)
            if path is None:
                continue

            if path != self.path:
                changed = True

            vflags = VnodeFlags(0)
            if e.fflags & getattr(select, "KQ_NOTE_WRITE", 0):
                vflags |= VnodeFlags.NOTE_WRITE
            if e.fflags & getattr(select, "KQ_NOTE_EXTEND", 0):
                vflags |= VnodeFlags.NOTE_EXTEND
            if e.fflags & getattr(select, "KQ_NOTE_DELETE", 0):
                vflags |= VnodeFlags.NOTE_DELETE
            if e.fflags & getattr(select, "KQ_NOTE_RENAME", 0):
                vflags |= VnodeFlags.NOTE_RENAME
            if e.fflags & getattr(select, "KQ_NOTE_ATTRIB", 0):
                vflags |= VnodeFlags.NOTE_ATTRIB
            if e.fflags & 0x00000080:  # NOTE_TRUNCATE
                vflags |= VnodeFlags.NOTE_TRUNCATE

            if e.fflags & (getattr(select, "KQ_NOTE_RENAME", 0) | getattr(select, "KQ_NOTE_DELETE", 0)):
                self._disarm_os_watch(path)

            if path == self.path:
                # Directory change: newly rotated DB/WAL files appeared
                before = set(self.handles)
                self.rescan()
                changed |= bool(set(self.handles) - before)

            self.emit_event(path, vflags or VnodeFlags.NOTE_WRITE)

        self.rescan()
        return changed

    def _arm_os_watch(self, p: Path, flags: VnodeFlags) -> None:
        """Open OS file descriptor with O_EVTONLY and add kevent to kqueue."""
        if not HAS_KQUEUE or self._queue is None:
            return
        if len(self.handles) >= self.max_watches:
            raise OSError(errno.EMFILE, "Too many open files")

        open_flags = getattr(os, "O_EVTONLY", os.O_RDONLY)
        try:
            fd = os.open(p, open_flags)
        except OSError as e:
            if e.errno in (errno.EMFILE, errno.ENFILE):
                raise OSError(errno.EMFILE, "Too many open files") from e
            return

        kq_fflags = 0
        if flags & VnodeFlags.NOTE_DELETE and hasattr(select, "KQ_NOTE_DELETE"):
            kq_fflags |= select.KQ_NOTE_DELETE
        if flags & VnodeFlags.NOTE_WRITE and hasattr(select, "KQ_NOTE_WRITE"):
            kq_fflags |= select.KQ_NOTE_WRITE
        if flags & VnodeFlags.NOTE_EXTEND and hasattr(select, "KQ_NOTE_EXTEND"):
            kq_fflags |= select.KQ_NOTE_EXTEND
        if flags & VnodeFlags.NOTE_ATTRIB and hasattr(select, "KQ_NOTE_ATTRIB"):
            kq_fflags |= select.KQ_NOTE_ATTRIB
        if flags & VnodeFlags.NOTE_RENAME and hasattr(select, "KQ_NOTE_RENAME"):
            kq_fflags |= select.KQ_NOTE_RENAME
        if flags & VnodeFlags.NOTE_REVOKE and hasattr(select, "KQ_NOTE_REVOKE"):
            kq_fflags |= select.KQ_NOTE_REVOKE
        if flags & VnodeFlags.NOTE_TRUNCATE:
            kq_fflags |= 0x00000080

        default_fflags = 0
        if hasattr(select, "KQ_NOTE_WRITE"):
            default_fflags |= select.KQ_NOTE_WRITE
        if hasattr(select, "KQ_NOTE_EXTEND"):
            default_fflags |= select.KQ_NOTE_EXTEND

        event = select.kevent(
            fd,
            filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
            fflags=kq_fflags or default_fflags,
        )
        try:
            self._queue.control([event], 0, 0)
            self.handles[p] = fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass

    def _disarm_os_watch(self, p: Path) -> None:
        """Close OS descriptor and remove from active handles."""
        fd = self.handles.pop(p, None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def close(self) -> None:
        """Shut down the monitor and release all file descriptors and kqueue."""
        if self._queue is not None:
            try:
                self._queue.close()
            except OSError:
                pass
            self._queue = None

        for fd in list(self.handles.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self.handles.clear()
        self.watches.clear()
        self.subscribers.clear()

    def __enter__(self) -> VnodeWatch:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


KqueueWatcher = VnodeWatch
ReferenceKqueueWatcher = VnodeWatch
