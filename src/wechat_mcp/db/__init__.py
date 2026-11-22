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

"""Database layer: multi-shard query engine, sender resolver, and decompression."""
from __future__ import annotations

from wechat_mcp.db.decompress import (
    MAX_CONTENT_BYTES,
    WCDB_CT_PLAIN,
    WCDB_CT_ZSTD,
    ZLIB_MAGIC,
    ZSTD_MAGIC,
    ContentDecodeError,
    ContentOverflowError,
    decompress_content,
)
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.db.sender import SenderResolver
from wechat_mcp.db.shards import ShardManager, md5_table

__all__ = [
    "HistoryReader",
    "ShardManager",
    "SenderResolver",
    "decompress_content",
    "md5_table",
    "MAX_CONTENT_BYTES",
    "WCDB_CT_PLAIN",
    "WCDB_CT_ZSTD",
    "ZLIB_MAGIC",
    "ZSTD_MAGIC",
    "ContentOverflowError",
    "ContentDecodeError",
]
