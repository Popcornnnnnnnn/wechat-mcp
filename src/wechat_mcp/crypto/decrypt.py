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

"""Pure-Python SQLCipher 4 AES-256-CBC decryption and encryption engine."""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import os
import struct
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger("wechat_mcp.crypto.decrypt")

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b"SQLite format 3\x00"

try:
    from Crypto.Cipher import AES

    def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)

    def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext)

except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """Derive SQLCipher 4 HMAC-SHA512 key using PBKDF2 (iterations=2, dklen=32)."""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_page1_hmac(page1: bytes, enc_key: bytes) -> bool:
    """Verify SQLCipher 4 Page 1 HMAC checksum. Returns True if key is valid."""
    if len(page1) < PAGE_SZ:
        return False
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac_mod.compare_digest(hm.digest(), p1_stored_hmac)


def verify_page_hmac(page_data: bytes, pgno: int, mac_key: bytes) -> bool:
    """Verify SQLCipher 4 HMAC checksum for arbitrary page."""
    if len(page_data) < PAGE_SZ:
        return False
    stored_hmac = page_data[PAGE_SZ - HMAC_SZ : PAGE_SZ]
    if pgno == 1:
        data = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    else:
        data = page_data[: PAGE_SZ - RESERVE_SZ + IV_SZ]
    hm = hmac_mod.new(mac_key, data, hashlib.sha512)
    hm.update(struct.pack("<I", pgno))
    return hmac_mod.compare_digest(hm.digest(), stored_hmac)


def decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """Decrypt single 4096-byte SQLCipher page to standard SQLite page with 80B reserve padding."""
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        ciphertext = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        decrypted = _aes_cbc_decrypt(enc_key, iv, ciphertext)
        return SQLITE_HDR + decrypted + (b"\x00" * RESERVE_SZ)
    else:
        ciphertext = page_data[: PAGE_SZ - RESERVE_SZ]
        decrypted = _aes_cbc_decrypt(enc_key, iv, ciphertext)
        return decrypted + (b"\x00" * RESERVE_SZ)


def encrypt_page(
    enc_key: bytes,
    mac_key: bytes,
    page_data: bytes,
    pgno: int,
    salt: Optional[bytes] = None,
) -> bytes:
    """Encrypt single 4096-byte SQLite page to SQLCipher 4 page (used for test fixtures)."""
    iv = os.urandom(IV_SZ)
    if pgno == 1:
        actual_salt = salt or os.urandom(SALT_SZ)
        to_encrypt = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        ciphertext = _aes_cbc_encrypt(enc_key, iv, to_encrypt)
        hm = hmac_mod.new(mac_key, ciphertext + iv, hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        return actual_salt + ciphertext + iv + hm.digest()
    else:
        to_encrypt = page_data[: PAGE_SZ - RESERVE_SZ]
        ciphertext = _aes_cbc_encrypt(enc_key, iv, to_encrypt)
        hm = hmac_mod.new(mac_key, ciphertext + iv, hashlib.sha512)
        hm.update(struct.pack("<I", pgno))
        return ciphertext + iv + hm.digest()


def decrypt_database(
    db_path: Union[str, Path],
    output_path: Union[str, Path],
    enc_key: Union[bytes, str],
    page_size: int = PAGE_SZ,
    reserve: int = RESERVE_SZ,
) -> bool:
    """Decrypt entire SQLCipher database to standard unencrypted SQLite.

    Returns True on success, False if file invalid or key incorrect.
    """
    path = Path(db_path)
    if not path.is_file():
        logger.warning("Database file not found: %s", db_path)
        return False

    file_size = path.stat().st_size
    if file_size < page_size:
        logger.warning("Database file too small: %d bytes (minimum %d)", file_size, page_size)
        return False

    if file_size % page_size != 0:
        logger.warning(
            "Database file size %d is not a multiple of %d (will process %d full pages)",
            file_size,
            page_size,
            file_size // page_size,
        )

    if isinstance(enc_key, str):
        try:
            key_bytes = bytes.fromhex(enc_key)
        except ValueError:
            key_bytes = enc_key.encode("utf-8")
    elif isinstance(enc_key, (bytes, bytearray)):
        key_bytes = bytes(enc_key)
    else:
        logger.warning("Invalid key type: %s", type(enc_key).__name__)
        return False

    if len(key_bytes) != KEY_SZ:
        logger.warning("Invalid key length: %d (expected %d)", len(key_bytes), KEY_SZ)
        return False

    dst = Path(output_path)
    temp_dst = dst.with_name(f"{dst.name}.tmp.{os.getpid()}")

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "rb") as fin:
            page1 = fin.read(page_size)
            if len(page1) < page_size:
                return False

            if not verify_page1_hmac(page1, key_bytes):
                logger.warning("Page 1 HMAC verification failed for %s (wrong key or corrupted)", path)
                return False

            salt = page1[:SALT_SZ]
            mac_key = derive_mac_key(key_bytes, salt)

            with open(temp_dst, "wb") as fout:
                dec_p1 = decrypt_page(key_bytes, page1, 1)
                fout.write(dec_p1)

                pgno = 2
                while True:
                    page_data = fin.read(page_size)
                    if len(page_data) < page_size:
                        break
                    if not verify_page_hmac(page_data, pgno, mac_key):
                        logger.warning(
                            "Page %d HMAC verification failed for %s (corrupted page)",
                            pgno,
                            path,
                        )
                        fout.close()
                        try:
                            if temp_dst.exists():
                                temp_dst.unlink()
                        except OSError:
                            pass
                        return False
                    dec_pn = decrypt_page(key_bytes, page_data, pgno)
                    fout.write(dec_pn)
                    pgno += 1

                fout.flush()
                os.fsync(fout.fileno())

        os.replace(temp_dst, dst)
        return True

    except Exception as e:
        logger.error("Error decrypting %s: %s", path, e)
        try:
            if temp_dst.exists():
                temp_dst.unlink()
        except OSError:
            pass
        return False


def encrypt_database(
    plain_path: Union[str, Path],
    enc_path: Union[str, Path],
    enc_key: Union[bytes, str],
    salt: Optional[bytes] = None,
    page_size: int = PAGE_SZ,
    reserve: int = RESERVE_SZ,
) -> None:
    """Encrypt plain SQLite DB with reserve bytes to SQLCipher 4 format (for synthetic tests)."""
    src = Path(plain_path)
    dst = Path(enc_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(enc_key, str):
        key_bytes = bytes.fromhex(enc_key)
    else:
        key_bytes = enc_key

    actual_salt = salt or os.urandom(SALT_SZ)
    mac_key = derive_mac_key(key_bytes, actual_salt)

    with open(src, "rb") as fin:
        plain_bytes = fin.read()

    total_pages = len(plain_bytes) // page_size
    with open(dst, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = plain_bytes[(pgno - 1) * page_size : pgno * page_size]
            enc_page = encrypt_page(
                key_bytes,
                mac_key,
                page,
                pgno,
                salt=actual_salt if pgno == 1 else None,
            )
            fout.write(enc_page)
