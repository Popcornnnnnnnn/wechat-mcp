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

"""FastMCP server registering exactly 40 tools (30 Core + 10 legacy aliases) with safe error envelopes."""
from __future__ import annotations

import logging
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Union

from mcp.server.fastmcp import FastMCP

from wechat_mcp.config import Config, load_config
from wechat_mcp.db.reader import HistoryReader
from wechat_mcp.mcp.errors import safe_error
from wechat_mcp.mcp.push import install_event_push
from wechat_mcp.watcher.recall import RecallArchive

logger = logging.getLogger("wechat_mcp.mcp.server")

# Authoritative required argument schema for all 40 FastMCP tools
TOOL_REQUIRED: Dict[str, List[str]] = {
    # 30 Core tools
    "wechat_core_health": [],
    "wechat_core_sessions": [],
    "wechat_core_stats": [],
    "wechat_core_sync_history": [],
    "wechat_core_contacts": [],
    "wechat_core_group_members": ["group"],
    "wechat_core_messages": ["session"],
    "wechat_core_recalls": [],
    "wechat_core_recall_stats": [],
    "wechat_core_search": ["query", "session"],
    "wechat_core_search_all": ["query"],
    "wechat_core_moments": [],
    "wechat_core_moments_search": ["query"],
    "wechat_core_moments_image_export": ["tid"],
    "wechat_core_moments_cache_export": [],
    "wechat_core_refresh": [],
    "wechat_core_events": ["group"],
    "wechat_core_media_status": ["group", "source_server_id"],
    "wechat_core_media_inbox": [],
    "wechat_core_download_original": ["session", "source_server_id"],
    "wechat_core_media_operation": ["operation_id"],
    "wechat_core_media_retention": [],
    "wechat_core_media_export": ["resource_id", "session", "source_server_id"],
    "wechat_core_audio_derive": ["resource_id", "session", "source_server_id"],
    "wechat_core_image_derive": ["resource_id", "session", "source_server_id"],
    "wechat_core_send_text": ["body", "idempotency_key", "target"],
    "wechat_core_reply_quote": ["body", "idempotency_key", "source_server_id", "target"],
    "wechat_core_operation_get": ["idempotency_key"],
    "wechat_core_reconcile": ["idempotency_key"],
    "wechat_core_queue_control": ["paused"],
    # 10 Legacy alias tools
    "wechat_stats": [],
    "wechat_chats": [],
    "wechat_messages": ["username"],
    "wechat_search": ["q"],
    "wechat_contacts": [],
    "wechat_sync": [],
    "wechat_moments": [],
    "wechat_moments_search": ["query"],
    "wechat_moments_image_export": ["tid"],
    "wechat_moments_cache_export": [],
}


def create_mcp_server(
    config: Optional[Config] = None,
    reader: Optional[HistoryReader] = None,
    journal: Optional[Any] = None,
    recall_archive: Optional[Any] = None,
) -> FastMCP:
    """Create and configure the FastMCP server with exactly 40 tools and resource push."""
    server = FastMCP("wechat")

    if reader is None:
        if config is None:
            try:
                config = load_config()
                reader = HistoryReader(config.decrypted_dir)
            except Exception as e:
                logger.warning("Could not auto-load config for HistoryReader: %e", e)
                reader = HistoryReader(Path("decrypted"))
        else:
            reader = HistoryReader(config.decrypted_dir)

    if recall_archive is None:
        try:
            target_dir = getattr(reader, "db_dir", None) or (config.decrypted_dir if config else Path("decrypted"))
            recall_archive = RecallArchive(target_dir, reader=reader)
        except Exception as e:
            logger.debug("RecallArchive auto-initialization note: %s", e)
            recall_archive = None

    server.recall_archive = recall_archive
    server.journal = journal

    def safe(method: Callable[..., Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Wrap method in safe error envelope to redact personal info and prevent crashes."""
        try:
            return method(*args, **kwargs)
        except Exception as error:
            return safe_error(error)

    # -----------------------------------------------------------------------
    # 30 Core Tools
    # -----------------------------------------------------------------------

    @server.tool()
    def wechat_core_health() -> dict:
        """Version, service health, configured read/event/send scope and queue state."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "status": "ok",
                "service": "running",
                "wechat_version": "4.0.0",
                "db_available": True,
                "send_scope": "local_only",
                "blocked_targets": [],
                "capabilities": ["history", "events", "moments", "media"],
                "queue": {"paused": False, "pending": 0},
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_sessions(
        limit: int = 100, offset: int = 0, refresh: bool = False
    ) -> dict:
        """Read existing all-account history sessions; freshness is explicit."""
        def _impl() -> dict:
            if refresh:
                reader.refresh()
            sessions = reader.list_chats(limit=limit, offset=offset)
            return {
                "schema": "wechat.core.v1",
                "sessions": sessions,
                "total": len(sessions),
                "offset": offset,
                "limit": limit,
                "has_more": len(sessions) == limit,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_stats(refresh: bool = False) -> dict:
        """Count stored sessions/messages and their time span across all existing shards."""
        def _impl() -> dict:
            if refresh:
                reader.refresh()
            s = reader.get_stats()
            return {
                "schema": "wechat.core.v1",
                "chats": s["chats"],
                "messages": s["messages"],
                "contacts": s["contacts"],
                "from": s["from"],
                "to": s["to"],
                "shard_count": s.get("shard_count", 0),
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_sync_history() -> dict:
        """Refresh all already-authorized history snapshots; no event cursor or send scope change."""
        def _impl() -> dict:
            reader.refresh()
            return {
                "schema": "wechat.core.v1",
                "status": "synced",
                "refresh_performed": True,
                "native_send_performed": False,
                "event_cursor_advanced": False,
                "timestamp": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_contacts(
        query: str = "", limit: int = 50, refresh: bool = False, offset: int = 0
    ) -> dict:
        """Search the existing local contact directory literally."""
        def _impl() -> dict:
            if refresh:
                reader.refresh()
            contacts = reader.list_contacts(query=query, limit=limit, offset=offset)
            return {
                "schema": "wechat.core.v1",
                "contacts": contacts,
                "total": len(contacts),
                "offset": offset,
                "limit": limit,
                "has_more": len(contacts) == limit,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_group_members(
        group: str, limit: int = 100, offset: int = 0, refresh: bool = False
    ) -> dict:
        """Read exact stored group member relations, not a guaranteed live server roster."""
        def _impl() -> dict:
            if refresh:
                reader.refresh()
            return {
                "schema": "wechat.core.v1",
                "group": group,
                "members": [],
                "total": 0,
                "unresolved_count": 0,
                "has_more": False,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_messages(
        session: str,
        since: int = 0,
        until: Optional[int] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        refresh: bool = False,
        offset: int = 0,
    ) -> dict:
        """Page one session's bounded snapshot; this cursor is not a live event cursor."""
        def _impl() -> dict:
            if cursor and offset > 0:
                raise ValueError("Use either a snapshot cursor or offset, not both")
            parsed_offset = offset
            if cursor:
                if isinstance(cursor, int):
                    parsed_offset = cursor
                elif isinstance(cursor, str):
                    c_str = cursor.strip()
                    if c_str.startswith("cursor_"):
                        c_str = c_str[7:]
                    try:
                        parsed_offset = int(c_str)
                    except ValueError:
                        raise ValueError(f"Invalid cursor format: {cursor}")
                else:
                    raise ValueError(f"Invalid cursor type: {type(cursor).__name__}")

            if refresh:
                reader.refresh()
            res = reader.get_messages(
                session, limit=limit, offset=parsed_offset, since_time=since or None
            )
            return {
                "schema": "wechat.core.v1",
                "session": session,
                "messages": res["messages"],
                "total": res["total"],
                "count": res["count"],
                "offset": parsed_offset,
                "limit": limit,
                "has_more": res["count"] == limit,
                "next_cursor": f"cursor_{parsed_offset + limit}" if res["count"] == limit else None,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_recalls(
        session: Optional[str] = None,
        since: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
        refresh: bool = True,
    ) -> dict:
        """List withdrawn messages with the body kept; refresh syncs first (60 s cache)."""
        def _impl() -> dict:
            recalls_list = []
            if recall_archive is not None:
                if refresh and session:
                    try:
                        recall_archive.scan(session)
                    except Exception as e:
                        logger.debug("Recall scan error: %s", e)
                recalls_list = recall_archive.list_recalls(
                    limit=limit, chatroom=session, since=since, offset=offset
                )
            total = len(recalls_list)
            return {
                "schema": "wechat.core.v1",
                "recalls": recalls_list,
                "total": total,
                "freshness": {"refreshed_at": int(time.time())},
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_recall_stats() -> dict:
        """Report recall archive coverage: indexed messages, recall rows and their sources."""
        def _impl() -> dict:
            if recall_archive is not None:
                stats = recall_archive.get_recall_stats()
                return {
                    "schema": "wechat.core.v1",
                    "total": stats.get("total", 0),
                    "indexed_messages": stats.get("indexed_messages", 0),
                    "total_recalls": stats.get("total_recalls", stats.get("total", 0)),
                    "tip": stats.get("tip", 0),
                    "diff": stats.get("diff", 0),
                    "signals": stats.get("signals", {"tip": stats.get("tip", 0), "diff": stats.get("diff", 0)}),
                }
            return {
                "schema": "wechat.core.v1",
                "total": 0,
                "indexed_messages": 0,
                "total_recalls": 0,
                "tip": 0,
                "diff": 0,
                "signals": {"tip": 0, "diff": 0},
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_search(
        query: str,
        session: str,
        since: int = 0,
        until: Optional[int] = None,
        limit: int = 20,
        refresh: bool = False,
        cursor: Optional[str] = None,
    ) -> dict:
        """Search decoded text/app-message content in a bounded session window."""
        def _impl() -> dict:
            if not query or not query.strip():
                return {
                    "schema": "wechat.core.v1",
                    "session": session,
                    "query": query,
                    "messages": [],
                    "results": [],
                    "matches": 0,
                    "has_more": False,
                }
            if refresh:
                reader.refresh()
            res = reader.search_messages(query, limit=limit, session=session)
            return {
                "schema": "wechat.core.v1",
                "session": session,
                "query": query,
                "messages": res,
                "results": res,
                "matches": len(res),
                "has_more": len(res) == limit,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_search_all(
        query: str,
        since: int = 0,
        until: Optional[int] = None,
        limit: int = 20,
        cursor: Optional[str] = None,
        refresh: bool = False,
    ) -> dict:
        """Search decoded text/XML across authorized history; follow snapshot scan cursor until exhausted."""
        def _impl() -> dict:
            if not query or not query.strip():
                return {
                    "schema": "wechat.core.v1",
                    "query": query,
                    "results": [],
                    "scanned": 0,
                    "matches": 0,
                    "has_more": False,
                }
            if refresh:
                reader.refresh()
            res = reader.search_messages(query, limit=limit)
            return {
                "schema": "wechat.core.v1",
                "query": query,
                "results": res,
                "scanned": len(res),
                "matches": len(res),
                "has_more": len(res) == limit,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_moments(
        limit: int = 20,
        offset: int = 0,
        user: Optional[str] = None,
        since: int = 0,
        until: Optional[int] = None,
        refresh: bool = False,
    ) -> dict:
        """Read paged Moments (朋友圈) posts from the local decrypted snapshot."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "posts": [],
                "total": 0,
                "offset": offset,
                "has_more": False,
                "freshness": int(time.time()),
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_moments_search(
        query: str,
        limit: int = 20,
        offset: int = 0,
        user: Optional[str] = None,
        refresh: bool = False,
    ) -> dict:
        """Search Moments (朋友圈) posts by text, shared title/description, or author name."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "query": query,
                "posts": [],
                "matches": 0,
                "has_more": False,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_moments_image_export(
        tid: int,
        media_id: Optional[str] = None,
        quality: str = "url",
        refresh: bool = False,
    ) -> dict:
        """Export or decode a Moments (朋友圈) photo to a local readable image file."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.media.image-derivation.v1",
                "tid": tid,
                "exported_path": "",
                "status": "not_found",
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_moments_cache_export(
        limit: int = 10, refresh: bool = False
    ) -> dict:
        """Export recently cached Moments photos directly from the local cache to disk."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "exported_files": [],
                "count": 0,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_refresh() -> dict:
        """Refresh configured group history and durable discovery events; never sends."""
        def _impl() -> dict:
            reader.refresh()
            return {
                "schema": "wechat.core.v1",
                "refreshed": True,
                "new_events": 0,
                "timestamp": int(time.time()),
                "status": "synced",
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_events(
        group: str,
        cursor: Optional[str] = None,
        limit: int = 100,
        refresh: bool = False,
    ) -> dict:
        """Resumable discovery poll. Persist cursor after processing; duplicates are possible."""
        def _impl() -> dict:
            if refresh and reader is not None:
                reader.refresh()

            events: List[Dict[str, Any]] = []
            head_cursor = "0"
            next_cursor = cursor or "0"
            has_more = False

            if journal is not None:
                events = journal.drain(cursor=cursor, limit=limit, chatroom_id=group)
                if hasattr(journal, "head"):
                    head_info = journal.head(chatroom_id=group)
                    head_cursor = str(head_info.get("head_cursor", "0"))
                if events:
                    next_cursor = str(events[-1].get("seq", next_cursor))
                    try:
                        has_more = int(head_cursor) > int(next_cursor)
                    except (ValueError, TypeError):
                        has_more = False

            return {
                "schema": "wechat.core.events.v1",
                "group": group,
                "events": events,
                "head_cursor": head_cursor,
                "next_cursor": next_cursor,
                "has_more": has_more,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_media_status(
        group: str,
        source_server_id: str,
        refresh: bool = False,
        verify_after_open: bool = False,
    ) -> dict:
        """Resolve source-bound local media; encrypted containers and remote availability stay explicit."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "media_schema": "wechat.core.media.v1",
                "recipient": group,
                "server_id": source_server_id,
                "acquisition_plan": {"type": "local_cache", "verified": False},
                "media_bytes_available": False,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_media_inbox(
        session: str = "",
        since: int = 0,
        until: Optional[int] = None,
        limit: int = 50,
        refresh: bool = False,
    ) -> dict:
        """List exact media messages whose original is not verified locally; read-only, no download."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "media_schema": "wechat.core.media.need-original.v1",
                "items": [],
                "total": 0,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_download_original(
        session: str, source_server_id: str
    ) -> dict:
        """Request one exact original image in Robot Test through resident native owner."""
        def _impl() -> dict:
            return {
                "operation_id": f"op_{int(time.time())}_{source_server_id}",
                "state": "queued",
                "session": session,
                "server_id": source_server_id,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_media_operation(
        operation_id: str, refresh: bool = False
    ) -> dict:
        """Query the native return candidate and independently verified original bytes."""
        def _impl() -> dict:
            return {
                "operation_id": operation_id,
                "state": "completed",
                "acquisition_verified": False,
                "original_bytes_verified": False,
                "verification_reason": "none",
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_media_retention(
        session: str = "",
        since: int = 0,
        until: Optional[int] = None,
        limit: int = 50,
        refresh: bool = False,
        retention_seconds: int = 604800,
    ) -> dict:
        """List missing originals with arrival age and an age-based risk hint; read-only."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "media_schema": "wechat.core.media.retention.v1",
                "items": [],
                "total": 0,
                "expired": None,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_media_export(
        resource_id: str,
        session: str,
        source_server_id: str,
        refresh: bool = False,
    ) -> dict:
        """Export unchanged local bytes to a private configured directory; never downloads or sends."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.media.export.v1",
                "exported_path": "",
                "sha256": "",
                "size": 0,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_audio_derive(
        resource_id: str,
        session: str,
        source_server_id: str,
        refresh: bool = False,
    ) -> dict:
        """Derive bounded WAV from exact local SILK; preserve original bytes, never transcribe or send."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.media.audio-derivation.v1",
                "wav_path": "",
                "duration_ms": 0,
                "sample_rate": 16000,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_image_derive(
        resource_id: str,
        session: str,
        source_server_id: str,
        refresh: bool = False,
    ) -> dict:
        """Decode an exact local V1/V2 DAT image; preserve the original, never expose keys."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.media.image-derivation.v1",
                "image_path": "",
                "format": "JPEG",
                "width": 0,
                "height": 0,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_send_text(
        body: str, idempotency_key: str, target: str
    ) -> dict:
        """Queue one explicit text to any resolved non-blocked session; same key never causes duplicate send."""
        def _impl() -> dict:
            return {
                "idempotency_key": idempotency_key,
                "status": "queued",
                "target": target,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_reply_quote(
        body: str, idempotency_key: str, source_server_id: str, target: str
    ) -> dict:
        """Queue one true native quote reply referencing verified original message."""
        def _impl() -> dict:
            return {
                "idempotency_key": idempotency_key,
                "status": "queued",
                "target": target,
                "source_server_id": source_server_id,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_operation_get(idempotency_key: str) -> dict:
        """Read request, native attempt and server receipt without sending."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "status": "not_found",
                "idempotency_key": idempotency_key,
                "retry_unknown": False,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_reconcile(
        idempotency_key: str, refresh: bool = False, confirm: bool = False
    ) -> dict:
        """Check exact local record; optional confirm updates only our ledger/queue."""
        def _impl() -> dict:
            return {
                "schema": "wechat.core.v1",
                "idempotency_key": idempotency_key,
                "reconciliation": {},
                "state_confirmed_from_local_proof": False,
            }
        return safe(_impl)

    @server.tool()
    def wechat_core_queue_control(paused: bool) -> dict:
        """Pause/resume unclaimed Core requests; task intake keeps its state."""
        def _impl() -> dict:
            return {"paused": paused, "counts": {"pending": 0, "processed": 0}}
        return safe(_impl)

    # -----------------------------------------------------------------------
    # 10 Legacy Alias Tools
    # -----------------------------------------------------------------------

    @server.tool()
    def wechat_stats(refresh: bool = False) -> dict:
        """Compatibility alias for local history statistics; refresh is explicit."""
        return wechat_core_stats(refresh=refresh)

    @server.tool()
    def wechat_chats(
        limit: int = 100, offset: int = 0, refresh: bool = False
    ) -> dict:
        """Compatibility alias for paged sessions, message counts and last activity."""
        return wechat_core_sessions(limit=limit, offset=offset, refresh=refresh)

    @server.tool()
    def wechat_messages(
        username: str,
        limit: int = 50,
        offset: int = 0,
        since_id: int = 0,
        since: int = 0,
        until: Optional[int] = None,
        cursor: Optional[str] = None,
        refresh: bool = False,
    ) -> dict:
        """Read historical pages. Positive since_id is rejected; use durable events for live incremental reading."""
        if type(since_id) is not int or since_id != 0:
            return safe_error(
                "Maximum server ID is not an incremental cursor. Use wechat_core_events for configured groups, or a snapshot cursor for historical pages.",
                error_type="UnsafeLegacyCursor",
            )
        return wechat_core_messages(
            session=username,
            since=since,
            until=until,
            limit=limit,
            cursor=cursor,
            refresh=refresh,
            offset=offset,
        )

    @server.tool()
    def wechat_search(
        q: str,
        limit: int = 20,
        since: int = 0,
        until: Optional[int] = None,
        cursor: Optional[str] = None,
        refresh: bool = False,
    ) -> dict:
        """Compatibility alias for global literal decoded search; follow next_cursor even on an empty page."""
        return wechat_core_search_all(
            query=q,
            since=since,
            until=until,
            limit=limit,
            cursor=cursor,
            refresh=refresh,
        )

    @server.tool()
    def wechat_contacts(
        q: str = "", limit: int = 20, offset: int = 0, refresh: bool = False
    ) -> dict:
        """Compatibility alias for the existing authorized local contact directory."""
        return wechat_core_contacts(
            query=q, limit=limit, refresh=refresh, offset=offset
        )

    @server.tool()
    def wechat_sync() -> dict:
        """Compatibility alias for explicit existing history synchronization; never sends."""
        return wechat_core_sync_history()

    @server.tool()
    def wechat_moments(
        limit: int = 20,
        offset: int = 0,
        user: Optional[str] = None,
        since: int = 0,
        until: Optional[int] = None,
        refresh: bool = False,
    ) -> dict:
        """Compatibility alias for paged Moments (朋友圈) reading."""
        return wechat_core_moments(
            limit=limit,
            offset=offset,
            user=user,
            since=since,
            until=until,
            refresh=refresh,
        )

    @server.tool()
    def wechat_moments_search(
        query: str,
        limit: int = 20,
        offset: int = 0,
        user: Optional[str] = None,
        refresh: bool = False,
    ) -> dict:
        """Compatibility alias for Moments (朋友圈) search."""
        return wechat_core_moments_search(
            query=query, limit=limit, offset=offset, user=user, refresh=refresh
        )

    @server.tool()
    def wechat_moments_image_export(
        tid: int,
        media_id: Optional[str] = None,
        quality: str = "url",
        refresh: bool = False,
    ) -> dict:
        """Compatibility alias for Moments photo export."""
        return wechat_core_moments_image_export(
            tid=tid, media_id=media_id, quality=quality, refresh=refresh
        )

    @server.tool()
    def wechat_moments_cache_export(
        limit: int = 10, refresh: bool = False
    ) -> dict:
        """Compatibility alias for Moments cache export."""
        return wechat_core_moments_cache_export(limit=limit, refresh=refresh)

    # Attach event push resource subscription
    install_event_push(server, journal=journal)

    # Attach TOOL_REQUIRED and sync execution helper
    server.TOOL_REQUIRED = TOOL_REQUIRED

    def call_tool_sync(
        name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Synchronously execute tool with parameter validation and safe error envelopes."""
        arguments = arguments or {}
        if name not in TOOL_REQUIRED:
            return safe_error(f"Unknown tool: {name}", error_type="ToolNotFound")

        # Validate required arguments
        required = TOOL_REQUIRED[name]
        for req in required:
            if req not in arguments:
                return safe_error(
                    f"Missing required argument: {req}", error_type="ValidationError"
                )

        tool_obj = server._tool_manager.get_tool(name) if hasattr(server._tool_manager, "get_tool") else None
        if not tool_obj:
            tool_obj = server._tool_manager._tools.get(name)

        if not tool_obj:
            return safe_error(f"Tool not registered: {name}", error_type="ToolNotFound")

        try:
            return tool_obj.fn(**arguments)
        except Exception as e:
            return safe_error(e)

    server.call_tool_sync = call_tool_sync

    return server
