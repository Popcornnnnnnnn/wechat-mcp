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

"""Database cataloging, snapshot isolation, 3-tier WAL checkpointing, and atomic sync."""
from __future__ import annotations

import json
import logging
import os
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from wechat_mcp.config import Config, WeChatConfig, load_config
from wechat_mcp.crypto.decrypt import decrypt_database

logger = logging.getLogger("wechat_mcp.crypto.sync")


class DatabaseCategory(str, Enum):
    CORE_SESSION = "session"
    CORE_CONTACT = "contact"
    CORE_MESSAGE = "message"
    MEDIA = "media"
    AUXILIARY = "auxiliary"


class SyncStatus(str, Enum):
    SYNCED = "synced"
    UP_TO_DATE = "up-to-date"
    SKIPPED_NO_SRC = "skip(no src)"
    SKIPPED_NO_KEY = "skip(no key)"
    FAILED = "failed"


@dataclass
class DatabaseEntry:
    rel_path: str                 # e.g. "message/message_0.db"
    abs_path: Path
    category: DatabaseCategory
    is_encrypted: bool
    has_wal: bool
    wal_size: int
    mtime: float
    wal_mtime: float


@dataclass
class SyncResult:
    rel_path: str
    status: SyncStatus
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class SyncSummary:
    total: int = 0
    synced: int = 0
    up_to_date: int = 0
    skipped: int = 0
    failed: int = 0
    results: List[SyncResult] = field(default_factory=list)


def is_sqlite_plaintext(path: Path) -> bool:
    """Check if file starts with standard SQLite format header."""
    if not path.is_file() or path.stat().st_size < 16:
        return False
    try:
        with open(path, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


class DatabaseCatalog:
    """Catalogs all databases in WeChat db_storage."""

    def __init__(self, db_dir: Path):
        self.db_dir = Path(db_dir).resolve()

    def scan(self) -> Dict[str, DatabaseEntry]:
        """Scan db_dir and return map of rel_path -> DatabaseEntry."""
        entries: Dict[str, DatabaseEntry] = {}
        if not self.db_dir.is_dir():
            return entries

        for root, _, files in os.walk(self.db_dir):
            for f in sorted(files):
                if not f.endswith(".db"):
                    continue
                if f.endswith(("-wal", "-shm", "-first.material", "-incremental.material", "-last.material", ".kvdb")):
                    continue

                abs_p = Path(root) / f
                try:
                    rel_p = abs_p.relative_to(self.db_dir).as_posix()
                    st = abs_p.stat()
                except OSError:
                    continue

                wal_p = Path(str(abs_p) + "-wal")
                has_wal = wal_p.is_file()
                wal_size = wal_p.stat().st_size if has_wal else 0
                wal_mtime = wal_p.stat().st_mtime if has_wal else 0.0

                # Determine category
                cat = DatabaseCategory.AUXILIARY
                if rel_p.startswith("session/"):
                    cat = DatabaseCategory.CORE_SESSION
                elif rel_p.startswith("contact/"):
                    cat = DatabaseCategory.CORE_CONTACT
                elif rel_p.startswith("message/"):
                    if "media_" in f or "biz_message_" in f:
                        cat = DatabaseCategory.MEDIA
                    else:
                        cat = DatabaseCategory.CORE_MESSAGE

                encrypted = not is_sqlite_plaintext(abs_p)
                entries[rel_p] = DatabaseEntry(
                    rel_path=rel_p,
                    abs_path=abs_p,
                    category=cat,
                    is_encrypted=encrypted,
                    has_wal=has_wal,
                    wal_size=wal_size,
                    mtime=st.st_mtime,
                    wal_mtime=wal_mtime,
                )
        return entries


def checkpoint_wal_cli(sqlcipher_bin: Path, snap_db: Path, key_hex: str, timeout: int = 60) -> bool:
    """Tier 1: Checkpoint WAL using sqlcipher CLI executable."""
    cmd = [
        str(sqlcipher_bin),
        str(snap_db),
        f"PRAGMA key = \"x'{key_hex}'\";",
        "PRAGMA wal_checkpoint(TRUNCATE);",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return res.returncode == 0


def checkpoint_wal_ctypes(snap_db: Path, key_bytes: bytes) -> bool:
    """Tier 2: Checkpoint WAL by dynamically loading libsqlcipher shared library."""
    import ctypes
    lib_names = [
        "/opt/homebrew/lib/libsqlcipher.dylib",
        "/usr/local/lib/libsqlcipher.dylib",
        "libsqlcipher.dylib",
        "libsqlcipher.so",
        "libsqlcipher.so.0",
    ]
    lib = None
    for name in lib_names:
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            continue
    if not lib:
        return False

    db_ptr = ctypes.c_void_p()
    if lib.sqlite3_open(str(snap_db).encode("utf-8"), ctypes.byref(db_ptr)) != 0:
        return False

    try:
        lib.sqlite3_key(db_ptr, key_bytes, len(key_bytes))
        errmsg = ctypes.c_char_p()
        rc = lib.sqlite3_exec(
            db_ptr,
            b"PRAGMA wal_checkpoint(TRUNCATE);",
            None,
            None,
            ctypes.byref(errmsg),
        )
        return rc == 0
    finally:
        lib.sqlite3_close(db_ptr)


def checkpoint_wal_pure_python(snap_db: Path, snap_wal: Path, page_size: int = 4096) -> bool:
    """Tier 3: Pure-Python SQLite WAL frame replayer (zero external binary dependencies)."""
    if not snap_wal.is_file() or snap_wal.stat().st_size <= 32:
        return True

    try:
        with open(snap_wal, "rb") as f_wal, open(snap_db, "r+b") as f_db:
            wal_hdr = f_wal.read(32)
            if len(wal_hdr) < 32:
                return False

            frame_len = 24 + page_size
            while True:
                frame = f_wal.read(frame_len)
                if len(frame) < frame_len:
                    break
                pgno = struct.unpack(">I", frame[:4])[0]
                if pgno == 0:
                    continue
                page_data = frame[24:frame_len]
                offset = (pgno - 1) * page_size
                f_db.seek(offset)
                f_db.write(page_data)

            f_db.flush()

        # Truncate WAL file to 0 bytes
        with open(snap_wal, "wb") as f_wal:
            f_wal.truncate(0)
        return True
    except Exception as e:
        logger.warning("Pure-Python WAL replay failed: %s", e)
        return False


def checkpoint_wal(
    snap_db: Path,
    snap_wal: Path,
    key: Union[str, bytes],
    sqlcipher_bin: Optional[Path] = None,
) -> bool:
    """Execute WAL checkpoint using the highest available tier."""
    if not snap_wal.is_file() or snap_wal.stat().st_size == 0:
        return True

    key_hex = key if isinstance(key, str) else key.hex()
    key_bytes = bytes.fromhex(key) if isinstance(key, str) else key

    # Tier 1: CLI
    if sqlcipher_bin and sqlcipher_bin.is_file():
        try:
            if checkpoint_wal_cli(sqlcipher_bin, snap_db, key_hex):
                return True
        except Exception as e:
            logger.debug("CLI checkpoint failed, falling back: %s", e)

    # Tier 2: ctypes
    try:
        if checkpoint_wal_ctypes(snap_db, key_bytes):
            return True
    except Exception as e:
        logger.debug("ctypes checkpoint failed, falling back: %s", e)

    # Tier 3: Pure-Python
    return checkpoint_wal_pure_python(snap_db, snap_wal)


def is_stale(src: Union[DatabaseEntry, Path], dst_path: Path) -> bool:
    """Check if source database or its WAL has newer writes than the decrypted file."""
    if not dst_path.is_file():
        return True

    try:
        dst_mtime = dst_path.stat().st_mtime
        if isinstance(src, DatabaseEntry):
            if src.mtime > dst_mtime:
                return True
            if src.has_wal and src.wal_size > 0 and src.wal_mtime > dst_mtime:
                return True
        else:
            if src.stat().st_mtime > dst_mtime:
                return True
            wal_p = Path(str(src) + "-wal")
            if wal_p.is_file() and wal_p.stat().st_size > 0 and wal_p.stat().st_mtime > dst_mtime:
                return True
    except OSError:
        return True
    return False


def sync_database_file(
    entry: DatabaseEntry,
    dst_path: Path,
    key: Union[str, bytes],
    sqlcipher_bin: Optional[Path] = None,
    force: bool = False,
    max_retries: int = 3,
) -> SyncResult:
    """Perform snapshot copy, WAL checkpoint, and atomic decryption with retry."""
    t0 = time.time()
    if not entry.abs_path.is_file():
        return SyncResult(entry.rel_path, SyncStatus.SKIPPED_NO_SRC)

    if not force and not is_stale(entry, dst_path):
        return SyncResult(entry.rel_path, SyncStatus.UP_TO_DATE)

    key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
    last_error: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        tmp_dir = tempfile.mkdtemp(prefix="wxmcp_sync_")
        try:
            snap_db = Path(tmp_dir) / "data.db"
            snap_wal = Path(tmp_dir) / "data.db-wal"
            snap_shm = Path(tmp_dir) / "data.db-shm"

            # 1. Snapshot copy
            shutil.copy2(entry.abs_path, snap_db)
            src_wal = Path(str(entry.abs_path) + "-wal")
            if src_wal.is_file():
                shutil.copy2(src_wal, snap_wal)
            src_shm = Path(str(entry.abs_path) + "-shm")
            if src_shm.is_file():
                shutil.copy2(src_shm, snap_shm)

            # 2. Checkpoint WAL into snap_db
            checkpoint_wal(snap_db, snap_wal, key, sqlcipher_bin)

            # 3. Decrypt to temporary file in destination directory (for atomic rename)
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            temp_dst = dst_path.with_name(f"{dst_path.name}.tmp.{os.getpid()}_{attempt}")

            if decrypt_database(snap_db, temp_dst, key_bytes):
                # 4. Atomic rename
                os.replace(temp_dst, dst_path)
                return SyncResult(entry.rel_path, SyncStatus.SYNCED, (time.time() - t0) * 1000)
            else:
                if temp_dst.exists():
                    try:
                        temp_dst.unlink()
                    except OSError:
                        pass
                raise RuntimeError("HMAC verification failed (inconsistent snapshot or key mismatch)")

        except Exception as e:
            last_error = e
            time.sleep(0.2 * attempt)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return SyncResult(entry.rel_path, SyncStatus.FAILED, (time.time() - t0) * 1000, str(last_error))


def sync_one_database(
    rel_path: str,
    src_root: Path,
    dst_root: Path,
    enc_key_hex: str,
    force: bool = False,
    max_retries: int = 3,
) -> str:
    """Sync single database with atomic snapshot, WAL checkpoint, and decrypt."""
    src_db = Path(src_root) / rel_path
    dst_db = Path(dst_root) / rel_path
    if not src_db.is_file():
        return "skip(no src)"

    entry = DatabaseEntry(
        rel_path=rel_path,
        abs_path=src_db,
        category=DatabaseCategory.AUXILIARY,
        is_encrypted=not is_sqlite_plaintext(src_db),
        has_wal=Path(str(src_db) + "-wal").is_file(),
        wal_size=Path(str(src_db) + "-wal").stat().st_size if Path(str(src_db) + "-wal").is_file() else 0,
        mtime=src_db.stat().st_mtime,
        wal_mtime=Path(str(src_db) + "-wal").stat().st_mtime if Path(str(src_db) + "-wal").is_file() else 0.0,
    )
    result = sync_database_file(
        entry=entry,
        dst_path=dst_db,
        key=enc_key_hex,
        force=force,
        max_retries=max_retries,
    )
    return result.status.value


def sync_all_databases(
    db_dir: Path,
    decrypted_dir: Path,
    keys: Dict[str, Union[str, Dict[str, Any]]],
    force: bool = False,
) -> Dict[str, int]:
    """Sync all databases mapped in keys dict. Returns summary statistics."""
    summary = {"synced": 0, "up-to-date": 0, "skipped": 0, "failed": 0}
    catalog = DatabaseCatalog(db_dir)
    entries = catalog.scan()

    for rel_path, entry in entries.items():
        if rel_path not in keys:
            summary["skipped"] += 1
            continue

        raw_val = keys[rel_path]
        key_hex = raw_val["enc_key"] if isinstance(raw_val, dict) else raw_val
        dst_path = decrypted_dir / rel_path

        res = sync_database_file(entry, dst_path, key_hex, force=force)
        if res.status == SyncStatus.SYNCED:
            summary["synced"] += 1
        elif res.status == SyncStatus.UP_TO_DATE:
            summary["up-to-date"] += 1
        elif res.status == SyncStatus.FAILED:
            summary["failed"] += 1
        else:
            summary["skipped"] += 1

    return summary


class SyncManager:
    """Orchestrates database cataloging, key loading, and incremental synchronization."""

    def __init__(self, config: Optional[WeChatConfig] = None):
        self.config = config or load_config()
        self.catalog = DatabaseCatalog(self.config.db_dir)
        self._last_sync_time: float = 0.0
        self._lock = threading.Lock()

    def load_keys(self) -> Dict[str, str]:
        """Load database keys mapping rel_path -> enc_key_hex."""
        if not self.config.keys_file.is_file():
            return {}
        try:
            with open(self.config.keys_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {
                rel: (info["enc_key"] if isinstance(info, dict) else info)
                for rel, info in raw.items()
            }
        except Exception as e:
            logger.warning("Failed to load keys file %s: %s", self.config.keys_file, e)
            return {}

    def sync_all(
        self,
        force: bool = False,
        categories: Optional[List[DatabaseCategory]] = None,
    ) -> SyncSummary:
        """Synchronize cataloged databases matching the specified categories."""
        with self._lock:
            keys = self.load_keys()
            entries = self.catalog.scan()
            summary = SyncSummary(total=len(entries))

            priority_order = [
                DatabaseCategory.CORE_SESSION,
                DatabaseCategory.CORE_CONTACT,
                DatabaseCategory.CORE_MESSAGE,
                DatabaseCategory.MEDIA,
                DatabaseCategory.AUXILIARY,
            ]
            sorted_entries = sorted(
                entries.values(),
                key=lambda e: priority_order.index(e.category) if e.category in priority_order else 99,
            )

            for entry in sorted_entries:
                if categories and entry.category not in categories:
                    continue

                if entry.rel_path not in keys:
                    summary.skipped += 1
                    summary.results.append(SyncResult(entry.rel_path, SyncStatus.SKIPPED_NO_KEY))
                    continue

                key = keys[entry.rel_path]
                dst_path = self.config.decrypted_dir / entry.rel_path
                res = sync_database_file(
                    entry,
                    dst_path,
                    key,
                    self.config.sqlcipher_bin,
                    force=force,
                )
                summary.results.append(res)
                if res.status == SyncStatus.SYNCED:
                    summary.synced += 1
                elif res.status == SyncStatus.UP_TO_DATE:
                    summary.up_to_date += 1
                elif res.status == SyncStatus.FAILED:
                    summary.failed += 1
                else:
                    summary.skipped += 1

            self._last_sync_time = time.time()
            return summary

    def fresh_sync(self, max_age_seconds: float = 30.0) -> bool:
        """Throttled sync called prior to queries in FastMCP and FastAPI."""
        if time.time() - self._last_sync_time < max_age_seconds:
            return False
        summary = self.sync_all(force=False)
        return summary.synced > 0
