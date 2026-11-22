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

"""Standardized safe error envelopes (wechat.core.error.v1) and sensitive data redaction."""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("wechat_mcp.mcp.errors")

ERROR_SCHEMA = "wechat.core.error.v1"

# Patterns for sensitive data redaction
_WXID_PATTERN = re.compile(r"wxid_[a-zA-Z0-9]{10,}")
_PATH_PATTERN = re.compile(r"/Users/[^/\s'\"]+")


def redact_sensitive(text: str) -> str:
    """Redact personal WeChat IDs, private paths, and authentication tokens."""
    if not text:
        return ""
    text = _WXID_PATTERN.sub("[REDACTED_WXID]", text)
    text = _PATH_PATTERN.sub("/Users/[USER]", text)
    return text


def redact_data(data: Any) -> Any:
    """Recursively redact sensitive strings within collections and values."""
    if isinstance(data, str):
        return redact_sensitive(data)
    elif isinstance(data, dict):
        return {
            (redact_sensitive(k) if isinstance(k, str) else k): redact_data(v)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_data(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(redact_data(item) for item in data)
    elif isinstance(data, set):
        return {redact_data(item) for item in data}
    return data


def safe_error(
    error: Union[Exception, str],
    error_type: Optional[str] = None,
    retry_unknown: bool = False,
    code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Produce standardized wechat.core.error.v1 envelope without leaking sensitive data."""
    if isinstance(error, Exception):
        err_name = error_type or type(error).__name__
        raw_msg = str(error) or err_name
    else:
        err_name = error_type or "Error"
        raw_msg = str(error)

    safe_msg = redact_sensitive(raw_msg)
    err_code = code or err_name
    sanitized_details = redact_data(details) if details else {}

    return {
        "schema": ERROR_SCHEMA,
        "error_type": err_name,
        "code": err_code,
        "message": safe_msg,
        "details": sanitized_details,
        "timestamp": int(time.time()),
        "retry_unknown": retry_unknown,
    }
