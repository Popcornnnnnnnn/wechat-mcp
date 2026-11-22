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

"""Synthetic test fixture generators for wechat-mcp."""
from tests.fixtures.crypto_generator import (
    PAGE_SZ,
    KEY_SZ,
    SALT_SZ,
    IV_SZ,
    HMAC_SZ,
    RESERVE_SZ,
    SQLITE_HDR,
    derive_mac_key,
    create_sqlite_db_with_reserve,
    encrypt_sqlite_db,
    generate_synthetic_encrypted_db,
    decrypt_database,
    decrypt_page,
    DecryptionError,
    HMACVerificationError,
    EmptyDatabaseError,
)
from tests.fixtures.wechat_generator import (
    TYPE_TEXT,
    TYPE_IMAGE,
    TYPE_VOICE,
    TYPE_APPMSG,
    TYPE_SYSMSG,
    TYPE_REVOKE,
    SUBTYPE_LINK,
    SUBTYPE_FILE,
    SUBTYPE_QUOTE,
    WCDB_CT_PLAIN,
    WCDB_CT_ZSTD,
    md5_table,
    SyntheticWeChatFixture,
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
    "create_sqlite_db_with_reserve",
    "encrypt_sqlite_db",
    "generate_synthetic_encrypted_db",
    "decrypt_database",
    "decrypt_page",
    "DecryptionError",
    "HMACVerificationError",
    "EmptyDatabaseError",
    "TYPE_TEXT",
    "TYPE_IMAGE",
    "TYPE_VOICE",
    "TYPE_APPMSG",
    "TYPE_SYSMSG",
    "TYPE_REVOKE",
    "SUBTYPE_LINK",
    "SUBTYPE_FILE",
    "SUBTYPE_QUOTE",
    "WCDB_CT_PLAIN",
    "WCDB_CT_ZSTD",
    "md5_table",
    "SyntheticWeChatFixture",
]
