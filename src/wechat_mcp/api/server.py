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

"""FastAPI REST query service hosted on port 8300 for local background intake scripts."""
from __future__ import annotations

import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from wechat_mcp.config import Config, load_config
from wechat_mcp.crypto.sync import SyncManager
from wechat_mcp.db.reader import HistoryReader

logger = logging.getLogger("wechat_mcp.api.server")


def create_api_app(
    config: Optional[Config] = None,
    reader: Optional[HistoryReader] = None,
) -> FastAPI:
    """Create FastAPI application exposing backwards-compatible REST endpoints on port 8300."""
    app = FastAPI(title="WeChat MCP REST Service", version="0.1.0")

    # Add CORS middleware for local background intake scripts and companion tools
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if reader is None:
        if config is None:
            try:
                config = load_config()
                reader = HistoryReader(config.decrypted_dir)
            except Exception as e:
                logger.warning("Could not load config for HistoryReader: %s", e)
                reader = HistoryReader(Path("decrypted"))
        else:
            reader = HistoryReader(config.decrypted_dir)

    @app.get("/api/stats")
    def get_stats() -> Dict[str, Any]:
        """Aggregate statistics across chats, messages, and contacts."""
        try:
            return reader.get_stats()
        except (FileNotFoundError, Exception) as e:
            logger.debug("Stats fallback on empty storage: %s", e)
            return {
                "chats": 0,
                "messages": 0,
                "contacts": 0,
                "from": 0,
                "to": int(time.time()),
                "shard_count": 0,
            }

    @app.get("/api/chats")
    def get_chats(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> List[Dict[str, Any]]:
        """List active chat sessions sorted by last_timestamp descending."""
        return reader.list_chats(limit=limit, offset=offset)

    @app.get("/api/chats/{username}/messages")
    def get_chat_messages(
        username: str,
        limit: int = 100,
        offset: int = 0,
        since_id: int = 0,
        type_: Optional[int] = Query(None, alias="type"),
        since_time: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Paged conversation message retrieval with optional since_id and type filter."""
        # Enforce memory bounds
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        return reader.get_messages(
            username=username,
            limit=limit,
            offset=offset,
            since_time=since_time,
            since_id=since_id,
            type_=type_,
        )

    @app.get("/api/contacts")
    def get_contacts(
        q: str = "",
        limit: int = Query(50, ge=1, le=1000),
    ) -> List[Dict[str, Any]]:
        """Search local contact directory filtered by nickname, remark, or alias."""
        return reader.list_contacts(query=q, limit=limit)

    @app.get("/api/search")
    def search_endpoint(
        q: str = Query(..., min_length=1),
        limit: int = Query(50, ge=1, le=1000),
    ) -> List[Dict[str, Any]]:
        """Global message content search across conversation tables."""
        return reader.search_messages(query=q, limit=limit)

    @app.post("/api/sync")
    def post_sync() -> Dict[str, Any]:
        """Trigger database sync and return execution summary."""
        logs = []
        if config is not None:
            try:
                manager = SyncManager(config)
                summary = manager.sync_all()
                logs = [f"Synced {summary.synced}/{summary.total} databases"]
            except Exception as e:
                logger.error("Sync error: %s", e)
                logs.append(f"Sync error: {e}")

        reader.refresh()
        return {
            "status": "sync_completed",
            "timestamp": int(time.time()),
            "log": logs,
        }

    return app
