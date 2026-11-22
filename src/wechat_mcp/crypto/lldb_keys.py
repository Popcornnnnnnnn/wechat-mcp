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

"""LLDB register inspection and breakpoint hooks for macOS WeChat encryption keys."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from wechat_mcp.crypto.decrypt import PAGE_SZ, verify_page1_hmac

logger = logging.getLogger("wechat_mcp.crypto.lldb_keys")


def get_key_registers(frame: Any) -> Tuple[Optional[int], Optional[int]]:
    """Extract (key_ptr, key_len) from stack frame supporting ARM64 and x86_64."""
    # 1. ARM64 calling convention: arg3=x3 (key_ptr), arg4=x4 (key_len)
    r_key = frame.FindRegister("x3")
    r_len = frame.FindRegister("x4")
    if r_key and r_key.IsValid() and r_len and r_len.IsValid():
        return r_key.GetValueAsUnsigned(), r_len.GetValueAsUnsigned()

    # 2. x86_64 calling convention: arg3=rcx (key_ptr), arg4=r8 (key_len)
    r_key = frame.FindRegister("rcx")
    r_len = frame.FindRegister("r8")
    if r_key and r_key.IsValid() and r_len and r_len.IsValid():
        return r_key.GetValueAsUnsigned(), r_len.GetValueAsUnsigned()

    return None, None


def collect_target_databases(db_dir: Path) -> Dict[str, bytes]:
    """Pre-scan db_storage and return dict of rel_path -> 4096-byte page 1."""
    targets: Dict[str, bytes] = {}
    if not db_dir.is_dir():
        return targets

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
                        targets[rel_p] = fp.read(PAGE_SZ)
            except OSError:
                continue
    return targets


def grab_key_from_frame(frame: Any, state: Dict[str, Any]) -> bool:
    """Callback for CommonCrypto CCCrypt/CCCryptorCreate breakpoints."""
    try:
        key_ptr, key_len = get_key_registers(frame)
        if not key_ptr or key_len != 32:
            return False

        process = frame.GetThread().GetProcess()
        error = getattr(frame, "error", None)
        try:
            # lldb SBProcess.ReadMemory(addr, size, error)
            import lldb  # type: ignore
            err = lldb.SBError()
            key_bytes = process.ReadMemory(key_ptr, 32, err)
            if not err.Success() or len(key_bytes) != 32:
                return False
        except Exception:
            return False

        seen_keys = state.setdefault("seen_keys", set())
        if key_bytes in seen_keys:
            return False
        seen_keys.add(key_bytes)

        target_dbs: Dict[str, bytes] = state.get("target_dbs", {})
        discovered: Dict[str, str] = state.setdefault("discovered", {})
        matched_any = False

        for rel_path, page1 in list(target_dbs.items()):
            if rel_path in discovered:
                continue
            if verify_page1_hmac(page1, key_bytes):
                discovered[rel_path] = key_bytes.hex()
                matched_any = True
                logger.info("Matched key for %s: %s", rel_path, key_bytes.hex())

        # If all target databases are matched, stop execution
        if target_dbs and len(discovered) >= len(target_dbs):
            state["complete"] = True

        return matched_any
    except Exception as e:
        logger.debug("Error in grab_key_from_frame: %s", e)
        return False


def verify_keys_file(keys_file: Path, db_dir: Path) -> Dict[str, bool]:
    """Verify keys in JSON file against actual Page 1 headers in db_dir."""
    results: Dict[str, bool] = {}
    if not keys_file.is_file() or not db_dir.is_dir():
        return results

    try:
        with open(keys_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Failed to parse keys file: %s", e)
        return results

    for rel_path, key_info in data.items():
        db_path = db_dir / rel_path
        if not db_path.is_file() or db_path.stat().st_size < PAGE_SZ:
            results[rel_path] = False
            continue

        raw_key = key_info["enc_key"] if isinstance(key_info, dict) else key_info
        try:
            key_bytes = bytes.fromhex(raw_key)
        except ValueError:
            results[rel_path] = False
            continue

        try:
            with open(db_path, "rb") as f:
                page1 = f.read(PAGE_SZ)
            results[rel_path] = verify_page1_hmac(page1, key_bytes)
        except OSError:
            results[rel_path] = False

    return results


def find_wechat_pid() -> Optional[int]:
    """Find running WeChat PID via pgrep."""
    try:
        res = subprocess.run(["pgrep", "-x", "WeChat"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            pids = res.stdout.strip().split()
            return int(pids[0])
    except Exception:
        pass
    return None


def run_lldb_extraction(
    db_dir: Path,
    output_keys_file: Path,
    pid: Optional[int] = None,
    timeout_seconds: int = 180,
) -> Dict[str, str]:
    """Launch LLDB process attached to WeChat, extract keys via breakpoints, and save JSON."""
    target_pid = pid or find_wechat_pid()
    if not target_pid:
        raise RuntimeError("WeChat process is not running. Please start WeChat first.")

    target_dbs = collect_target_databases(db_dir)
    if not target_dbs:
        logger.warning("No .db files found in %s", db_dir)
        return {}

    # Create temporary python script for LLDB to execute
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as script_file:
        script_code = f"""
import lldb
import json
import struct
import hashlib
import hmac as hmac_mod
from pathlib import Path

KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
PAGE_SZ = 4096
RESERVE_SZ = 80

def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)

def verify_page1(page1, enc_key):
    if len(page1) < PAGE_SZ:
        return False
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored = page1[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    hm = hmac_mod.new(mac_key, data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(hm.digest(), stored)

db_pages = {{}}
db_dir = Path({json.dumps(str(db_dir))})
for rel in {json.dumps(list(target_dbs.keys()))}:
    p = db_dir / rel
    if p.is_file() and p.stat().st_size >= PAGE_SZ:
        with open(p, "rb") as f:
            db_pages[rel] = f.read(PAGE_SZ)

discovered = {{}}
seen_keys = set()
output_path = Path({json.dumps(str(output_keys_file))})

def bp_callback(frame, bp_loc, dict_):
    r_key = frame.FindRegister("x3")
    r_len = frame.FindRegister("x4")
    if not (r_key and r_key.IsValid() and r_len and r_len.IsValid()):
        r_key = frame.FindRegister("rcx")
        r_len = frame.FindRegister("r8")
    if not (r_key and r_key.IsValid() and r_len and r_len.IsValid()):
        return False
    key_ptr = r_key.GetValueAsUnsigned()
    key_len = r_len.GetValueAsUnsigned()
    if key_len != 32:
        return False

    process = frame.GetThread().GetProcess()
    err = lldb.SBError()
    key_bytes = process.ReadMemory(key_ptr, 32, err)
    if not err.Success() or len(key_bytes) != 32:
        return False
    if key_bytes in seen_keys:
        return False
    seen_keys.add(key_bytes)

    for rel, p1 in db_pages.items():
        if rel in discovered:
            continue
        if verify_page1(p1, key_bytes):
            discovered[rel] = {{"enc_key": key_bytes.hex()}}
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as out_f:
                json.dump(discovered, out_f, indent=2)

    return False
"""
        script_file.write(script_code)
        script_file_path = script_file.name

    try:
        lldb_cmd = [
            "lldb",
            "-p",
            str(target_pid),
            "-o",
            f"command script import {script_file_path}",
            "-o",
            "breakpoint set -n CCCrypt -F bp_callback",
            "-o",
            "breakpoint set -n CCCryptorCreate -F bp_callback",
            "-o",
            "continue",
            "-o",
            "quit",
        ]
        subprocess.run(lldb_cmd, timeout=timeout_seconds, capture_output=True)
    except Exception as e:
        logger.error("LLDB execution error: %s", e)
    finally:
        try:
            os.unlink(script_file_path)
        except OSError:
            pass

    # Read discovered keys
    if output_keys_file.is_file():
        try:
            with open(output_keys_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {
                rel: (v["enc_key"] if isinstance(v, dict) else v)
                for rel, v in raw.items()
            }
        except Exception:
            pass
    return {}
