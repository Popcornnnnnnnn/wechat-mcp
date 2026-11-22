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

"""WCDB message content decompression engine supporting zstandard, zlib, and bounded memory caps."""
from __future__ import annotations

import logging
from typing import Any, Optional
import zlib

try:
    import zstandard
except ImportError:
    zstandard = None

logger = logging.getLogger("wechat_mcp.db.decompress")

# Magic byte signatures
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ZLIB_MAGIC = b"\x78"

# Maximum allowed size for decompressed text (256 KB)
MAX_CONTENT_BYTES: int = 256 * 1024

# WCDB column type compression flags
WCDB_CT_PLAIN: int = 0
WCDB_CT_ZSTD: int = 4


class ContentOverflowError(ValueError):
    """Decompressed payload exceeds bounded byte limit."""
    pass


class ContentDecodeError(ValueError):
    """Payload is corrupted or not valid UTF-8 text."""
    pass


def decompress_content(
    content: Any,
    wc_ct: Optional[int] = None,
    compress_col: Optional[bytes] = None,
    max_bytes: int = MAX_CONTENT_BYTES,
) -> str:
    """Decompress WCDB message content from message_content or compress_content columns.

    Order of evaluation:
    1. Check compress_col (legacy zlib compressed column)
    2. If content is already str: truncate if over max_bytes, else return
    3. If content is bytes:
       a. Check ZSTD magic header or wc_ct == 4 -> decompress with zstandard
       b. Check ZLIB magic header (0x78) -> decompress with zlib / raw deflate
       c. Fallback to direct UTF-8 decode
    4. Safe fallback to [Decompression Failed] on corrupted data, or [Binary Data]
    """
    # 1. Check legacy compress_content column
    if compress_col:
        try:
            decomp = zlib.decompress(compress_col)
            if len(decomp) > max_bytes:
                return decomp[:max_bytes].decode("utf-8", errors="replace") + "... [TRUNCATED]"
            return decomp.decode("utf-8", errors="replace")
        except Exception:
            try:
                # Raw deflate fallback (-15)
                decomp = zlib.decompress(compress_col, -15)
                if len(decomp) > max_bytes:
                    return decomp[:max_bytes].decode("utf-8", errors="replace") + "... [TRUNCATED]"
                return decomp.decode("utf-8", errors="replace")
            except Exception:
                return "[Decompression Failed]"

    # 2. String payload
    if isinstance(content, str):
        if len(content.encode("utf-8", errors="replace")) > max_bytes:
            return content[:max_bytes] + "... [TRUNCATED]"
        return content

    # 3. None or empty
    if content is None or content == b"":
        return ""

    # 4. Bytes payload
    if isinstance(content, bytes):
        # 4a. Zstandard decompression
        if content.startswith(ZSTD_MAGIC) or wc_ct == WCDB_CT_ZSTD:
            if not zstandard:
                return "[Decompression Failed]"
            try:
                # Check declared frame size if available for decompression bomb protection
                try:
                    declared_size = zstandard.frame_content_size(content)
                    if declared_size > max_bytes * 10:  # Suspicious compression bomb
                        return "[Content Overflow]"
                except Exception:
                    pass

                dctx = zstandard.ZstdDecompressor()
                decomp = dctx.decompress(content, max_output_size=max_bytes + 1024)
                if len(decomp) > max_bytes:
                    return decomp[:max_bytes].decode("utf-8", errors="replace") + "... [TRUNCATED]"
                return decomp.decode("utf-8", errors="replace")
            except Exception:
                return "[Decompression Failed]"

        # 4b. Zlib decompression
        if content.startswith(ZLIB_MAGIC):
            try:
                decomp = zlib.decompress(content)
                if len(decomp) > max_bytes:
                    return decomp[:max_bytes].decode("utf-8", errors="replace") + "... [TRUNCATED]"
                return decomp.decode("utf-8", errors="replace")
            except Exception:
                try:
                    decomp = zlib.decompress(content, -15)
                    if len(decomp) > max_bytes:
                        return decomp[:max_bytes].decode("utf-8", errors="replace") + "... [TRUNCATED]"
                    return decomp.decode("utf-8", errors="replace")
                except Exception:
                    return "[Decompression Failed]"

        # 4c. Plain UTF-8 bytes fallback
        try:
            decoded = content.decode("utf-8")
            if len(content) > max_bytes:
                return decoded[:max_bytes] + "... [TRUNCATED]"
            return decoded
        except UnicodeDecodeError:
            return "[Binary Data]"

    return ""
