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

"""Cryptographic key extraction, SQLCipher decryption, and database sync."""

from wechat_mcp.crypto.decrypt import (
    PAGE_SZ,
    KEY_SZ,
    SALT_SZ,
    IV_SZ,
    HMAC_SZ,
    RESERVE_SZ,
    SQLITE_HDR,
    derive_mac_key,
    verify_page1_hmac,
    verify_page_hmac,
    decrypt_page,
    encrypt_page,
    decrypt_database,
    encrypt_database,
)

__all__ = [
    "PAGE_SZ",
    "KEY_SZ",
    "SALT_SZ",
    "IV_SZ",
    "HMAC_SZ",
    "RESERVE_SZ",
    "SQLITE_HDR",
    "derive_mac_key",
    "verify_page1_hmac",
    "verify_page_hmac",
    "decrypt_page",
    "encrypt_page",
    "decrypt_database",
    "encrypt_database",
]
