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
Pure-Python SQLCipher 4 Synthetic Fixture Generator and Round-Trip Decryptor.

Generates and decrypts SQLCipher 4 AES-256-CBC encrypted SQLite databases
with PBKDF2-HMAC-SHA512 key derivation, reserve=80 bytes, and per-page HMAC.
Zero external sqlcipher CLI or broken dynamic library dependencies.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import os
from pathlib import Path
import struct
import tempfile
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PAGE_SZ: int = 4096
KEY_SZ: int = 32
SALT_SZ: int = 16
IV_SZ: int = 16
HMAC_SZ: int = 64
RESERVE_SZ: int = 80  # IV_SZ (16) + HMAC_SZ (64) = 80
SQLITE_HDR: bytes = b"SQLite format 3\x00"


class DecryptionError(Exception):
    """Raised when database decryption fails."""


class HMACVerificationError(DecryptionError):
    """Raised when HMAC verification fails on page authentication."""


class EmptyDatabaseError(DecryptionError):
    """Raised when input database file is empty or missing."""


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """
    Derive HMAC-SHA512 key from raw 32-byte encryption key and masked salt.
    Formula: mac_salt = salt ^ 0x3A; PBKDF2-HMAC-SHA512(enc_key, mac_salt, iterations=2, dklen=32).
    """
    if len(enc_key) != KEY_SZ:
        raise ValueError(f"enc_key must be {KEY_SZ} bytes (got {len(enc_key)})")
    if len(salt) != SALT_SZ:
        raise ValueError(f"salt must be {SALT_SZ} bytes (got {len(salt)})")

    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def create_sqlite_db_with_reserve(
    db_path: Union[str, Path],
    sql_script: str = "",
    reserve_bytes: int = 80,
    page_size: int = 4096,
) -> None:
    """
    Create a standard SQLite database with explicit reserve bytes per page using ctypes.
    Uses sqlite3_file_control with SQLITE_FCNTL_RESERVE_BYTES (opcode 38) and VACUUM;.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    lib_name = ctypes.util.find_library("sqlite3") or "libsqlite3.dylib"
    lib = ctypes.CDLL(lib_name)
    db_ptr = ctypes.c_void_p()

    rc = lib.sqlite3_open(str(db_path).encode("utf-8"), ctypes.byref(db_ptr))
    if rc != 0:
        raise RuntimeError(f"sqlite3_open failed with error code: {rc}")

    try:
        # SQLITE_FCNTL_RESERVE_BYTES = 38
        n_bytes = ctypes.c_int(reserve_bytes)
        res = lib.sqlite3_file_control(db_ptr, b"main", 38, ctypes.byref(n_bytes))
        if res != 0:
            raise RuntimeError(f"sqlite3_file_control(RESERVE_BYTES) failed: {res}")

        lib.sqlite3_exec(
            db_ptr, f"PRAGMA page_size = {page_size};".encode("utf-8"), None, None, None
        )
        lib.sqlite3_exec(db_ptr, b"VACUUM;", None, None, None)
        if sql_script:
            lib.sqlite3_exec(db_ptr, sql_script.encode("utf-8"), None, None, None)
    finally:
        lib.sqlite3_close(db_ptr)


def encrypt_sqlite_db(
    plain_path: Union[str, Path],
    enc_path: Union[str, Path],
    enc_key: Union[bytes, str],
    salt: Optional[bytes] = None,
) -> None:
    """
    Encrypt a SQLite database (formatted with reserve=80) using SQLCipher 4 AES-256-CBC.
    """
    if isinstance(enc_key, str):
        enc_key = bytes.fromhex(enc_key)
    if len(enc_key) != KEY_SZ:
        raise ValueError(f"enc_key must be {KEY_SZ} bytes (got {len(enc_key)})")

    if salt is None:
        salt = os.urandom(SALT_SZ)
    elif len(salt) != SALT_SZ:
        raise ValueError(f"salt must be {SALT_SZ} bytes (got {len(salt)})")

    mac_key = derive_mac_key(enc_key, salt)

    plain_path = Path(plain_path)
    enc_path = Path(enc_path)
    file_size = plain_path.stat().st_size

    if file_size == 0:
        raise EmptyDatabaseError("Cannot encrypt empty database file")
    if file_size % PAGE_SZ != 0:
        raise ValueError(f"Database size {file_size} is not a multiple of page size {PAGE_SZ}")

    total_pages = file_size // PAGE_SZ
    enc_path.parent.mkdir(parents=True, exist_ok=True)

    with open(plain_path, "rb") as fin, open(enc_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                break
            iv = os.urandom(IV_SZ)

            if pgno == 1:
                # Page 1: [0:16] Salt, [16:4016] Ciphertext, [4016:4032] IV, [4032:4096] HMAC
                body = page[SALT_SZ : PAGE_SZ - RESERVE_SZ]
                encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
                ct = encryptor.update(body) + encryptor.finalize()

                h = hmac.new(mac_key, ct + iv, hashlib.sha512)
                h.update(struct.pack("<I", 1))
                tag = h.digest()
                fout.write(salt + ct + iv + tag)
            else:
                # Pages 2..N: [0:4016] Ciphertext, [4016:4032] IV, [4032:4096] HMAC
                body = page[: PAGE_SZ - RESERVE_SZ]
                encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
                ct = encryptor.update(body) + encryptor.finalize()

                h = hmac.new(mac_key, ct + iv, hashlib.sha512)
                h.update(struct.pack("<I", pgno))
                tag = h.digest()
                fout.write(ct + iv + tag)


def generate_synthetic_encrypted_db(
    enc_key: Union[bytes, str],
    sql_script: str = "",
    output_path: Optional[Union[str, Path]] = None,
    salt: Optional[bytes] = None,
) -> Path:
    """Helper to create and encrypt a synthetic SQLCipher database in one call."""
    if isinstance(enc_key, str):
        enc_key = bytes.fromhex(enc_key)

    if output_path is None:
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        output_path = Path(tmp)
    else:
        output_path = Path(output_path)

    with tempfile.TemporaryDirectory() as td:
        plain_path = Path(td) / "plain.db"
        create_sqlite_db_with_reserve(plain_path, sql_script)
        encrypt_sqlite_db(plain_path, output_path, enc_key, salt=salt)

    return output_path


def decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """Decrypt a single page of SQLCipher 4 database."""
    if len(page_data) != PAGE_SZ:
        raise ValueError(f"Page data must be {PAGE_SZ} bytes (got {len(page_data)})")

    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]

    if pgno == 1:
        ct = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        return SQLITE_HDR + pt + (b"\x00" * RESERVE_SZ)
    else:
        ct = page_data[: PAGE_SZ - RESERVE_SZ]
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt + (b"\x00" * RESERVE_SZ)


def decrypt_database(
    db_path: Union[str, Path],
    out_path: Union[str, Path],
    enc_key: Union[bytes, str],
    verify_all_pages: bool = False,
) -> bool:
    """
    Pure-Python SQLCipher 4 Decryptor.
    Decrypts encrypted database to standard SQLite database with reserve=80 preserved.
    Returns True on success, False or raises DecryptionError on failure.
    """
    if isinstance(enc_key, str):
        try:
            enc_key = bytes.fromhex(enc_key)
        except ValueError as e:
            raise ValueError(f"Invalid hexadecimal key representation: {e}") from e

    if len(enc_key) != KEY_SZ:
        raise ValueError(f"Invalid key length: expected {KEY_SZ} bytes (got {len(enc_key)})")

    db_path = Path(db_path)
    out_path = Path(out_path)

    if not db_path.exists():
        raise FileNotFoundError(f"Database file not found: {db_path}")

    file_size = db_path.stat().st_size
    if file_size == 0:
        raise EmptyDatabaseError(f"Database file is empty: {db_path}")

    if file_size < PAGE_SZ:
        raise DecryptionError("Corrupted database header: file smaller than page size")

    if file_size % PAGE_SZ != 0:
        raise ValueError(f"Database size {file_size} must be multiple of page size {PAGE_SZ}")

    total_pages = file_size // PAGE_SZ

    with open(db_path, "rb") as fin:
        page1 = fin.read(PAGE_SZ)

    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)

    # Verify Page 1 HMAC
    p1_ct_iv = page1[SALT_SZ : PAGE_SZ - HMAC_SZ]
    p1_stored_tag = page1[PAGE_SZ - HMAC_SZ :]
    h1 = hmac.new(mac_key, p1_ct_iv, hashlib.sha512)
    h1.update(struct.pack("<I", 1))

    if not hmac.compare_digest(h1.digest(), p1_stored_tag):
        raise HMACVerificationError("Page 1 HMAC verification failed: wrong key or corrupted header")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                raise DecryptionError(f"Unexpected EOF reading page {pgno}")

            if verify_all_pages and pgno > 1:
                ct_iv = page[: PAGE_SZ - HMAC_SZ]
                tag = page[PAGE_SZ - HMAC_SZ :]
                h = hmac.new(mac_key, ct_iv, hashlib.sha512)
                h.update(struct.pack("<I", pgno))
                if not hmac.compare_digest(h.digest(), tag):
                    raise HMACVerificationError(f"HMAC verification failed on page {pgno}")

            decrypted_page = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted_page)

    return True
