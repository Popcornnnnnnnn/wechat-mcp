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

"""FastMCP Server module exposing 40 tools, resource push, and safe error envelopes."""
from __future__ import annotations

from wechat_mcp.mcp.errors import ERROR_SCHEMA, redact_sensitive, safe_error
from wechat_mcp.mcp.push import EventPush, install_event_push
from wechat_mcp.mcp.server import TOOL_REQUIRED, create_mcp_server

__all__ = [
    "create_mcp_server",
    "safe_error",
    "redact_sensitive",
    "TOOL_REQUIRED",
    "EventPush",
    "install_event_push",
    "ERROR_SCHEMA",
]
