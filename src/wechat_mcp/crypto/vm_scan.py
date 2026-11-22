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

"""Pure-Python ctypes Mach VM memory scanner for macOS WeChat (fallback for WeChat 4.0)."""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from wechat_mcp.crypto.decrypt import PAGE_SZ, SALT_SZ, verify_page1_hmac
from wechat_mcp.crypto.lldb_keys import find_wechat_pid

logger = logging.getLogger("wechat_mcp.crypto.vm_scan")

VM_PROT_READ = 0x01
VM_PROT_WRITE = 0x02
VM_REGION_BASIC_INFO_64 = 9
CHUNK_SIZE = 2 * 1024 * 1024  # 2MB chunks
HEX_PATTERN = re.compile(rb"x'([0-9a-fA-F]{64})([0-9a-fA-F]{32})'")


class MachVMScanner:
    """Memory scanner using macOS Mach VM kernel APIs via ctypes."""

    def __init__(self, pid: int):
        self.pid = pid
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"))
        self._setup_bindings()
        self.task = self._get_task()

    def _setup_bindings(self) -> None:
        self._libc.mach_task_self.restype = ctypes.c_uint32

        self._libc.task_for_pid.argtypes = [
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._libc.task_for_pid.restype = ctypes.c_int

        self._libc.mach_vm_region.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._libc.mach_vm_region.restype = ctypes.c_int

        self._libc.mach_vm_read.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._libc.mach_vm_read.restype = ctypes.c_int

        self._libc.mach_vm_deallocate.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.c_uint64,
        ]
        self._libc.mach_vm_deallocate.restype = ctypes.c_int

    def _get_task(self) -> int:
        task = ctypes.c_uint32(0)
        self_task = self._libc.mach_task_self()
        kr = self._libc.task_for_pid(self_task, self.pid, ctypes.byref(task))
        if kr != 0:
            raise PermissionError(
                f"task_for_pid failed with kern_return_t={kr}. "
                "Ensure the process is run with root/sudo or appropriate debugging entitlements."
            )
        return task.value

    def scan_for_raw_keys(self) -> List[Tuple[str, str]]:
        """Scan process writable memory regions for x'<64 hex key><32 hex salt>' patterns."""
        results: List[Tuple[str, str]] = []
        seen = set()

        address = ctypes.c_uint64(0)
        size = ctypes.c_uint64(0)
        info = (ctypes.c_int32 * 9)()
        info_cnt = ctypes.c_uint32(9)
        object_name = ctypes.c_uint32(0)

        data_ptr = ctypes.c_size_t(0)
        data_cnt = ctypes.c_uint32(0)

        overlap = 99

        while True:
            kr = self._libc.mach_vm_region(
                self.task,
                ctypes.byref(address),
                ctypes.byref(size),
                VM_REGION_BASIC_INFO_64,
                ctypes.byref(info),
                ctypes.byref(info_cnt),
                ctypes.byref(object_name),
            )
            if kr != 0:
                break

            prot = info[0]
            region_addr = address.value
            region_size = size.value

            # Filter for readable + writable memory regions
            if (prot & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE):
                curr = region_addr
                end = region_addr + region_size

                while curr < end:
                    chunk_sz = min(CHUNK_SIZE, end - curr)
                    read_kr = self._libc.mach_vm_read(
                        self.task,
                        curr,
                        chunk_sz,
                        ctypes.byref(data_ptr),
                        ctypes.byref(data_cnt),
                    )
                    if read_kr == 0 and data_cnt.value > 0:
                        raw_buf = ctypes.string_at(data_ptr.value, data_cnt.value)
                        for match in HEX_PATTERN.finditer(raw_buf):
                            key_hex = match.group(1).decode("ascii").lower()
                            salt_hex = match.group(2).decode("ascii").lower()
                            pair = (key_hex, salt_hex)
                            if pair not in seen:
                                seen.add(pair)
                                results.append(pair)

                        self._libc.mach_vm_deallocate(self._libc.mach_task_self(), data_ptr.value, data_cnt.value)

                    if chunk_sz <= overlap:
                        break
                    curr += (chunk_sz - overlap)

            address.value = region_addr + region_size

        return results


def scan_process_keys(
    pid: Optional[int] = None,
    db_dir: Optional[Path] = None,
) -> Dict[str, str]:
    """Scan WeChat process memory for SQLCipher keys and match against databases in db_dir."""
    target_pid = pid or find_wechat_pid()
    if not target_pid:
        raise RuntimeError("WeChat process is not running.")

    scanner = MachVMScanner(target_pid)
    raw_keys = scanner.scan_for_raw_keys()
    if not raw_keys:
        return {}

    # Match against databases
    matched_keys: Dict[str, str] = {}
    if not db_dir or not db_dir.is_dir():
        return {f"key_{i}": k[0] for i, k in enumerate(raw_keys)}

    # Read salt from page 1 of each DB
    db_salts: Dict[str, Tuple[bytes, bytes]] = {}  # rel_path -> (salt_bytes, page1)
    for root, _, files in os.walk(db_dir):
        for f in files:
            if not f.endswith(".db"):
                continue
            if f.endswith(("-wal", "-shm", "-first.material", "-incremental.material", "-last.material", ".kvdb")):
                continue
            abs_p = Path(root) / f
            try:
                rel_p = abs_p.relative_to(db_dir).as_posix()
                if abs_p.stat().st_size >= PAGE_SZ:
                    with open(abs_p, "rb") as fp:
                        page1 = fp.read(PAGE_SZ)
                        db_salts[rel_p] = (page1[:SALT_SZ], page1)
            except OSError:
                continue

    for key_hex, salt_hex in raw_keys:
        try:
            salt_bytes = bytes.fromhex(salt_hex)
            key_bytes = bytes.fromhex(key_hex)
        except ValueError:
            continue

        for rel_path, (db_salt, page1) in db_salts.items():
            if rel_path in matched_keys:
                continue
            if db_salt == salt_bytes and verify_page1_hmac(page1, key_bytes):
                matched_keys[rel_path] = key_hex
                logger.info("Mach VM matched %s: %s", rel_path, key_hex)

    return matched_keys
