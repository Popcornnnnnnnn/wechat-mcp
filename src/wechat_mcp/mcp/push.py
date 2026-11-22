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

"""Event subscription and resource push (wechat-core://events/{group}) over MCP resource protocol."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote

from pydantic import AnyUrl

logger = logging.getLogger("wechat_mcp.mcp.push")

SCHEMA = "wechat.core.event-resource.v1"


class EventPush:
    """Bounded, per-session resource hints over durable WeChat events."""

    def __init__(
        self,
        journal: Optional[Any] = None,
        groups: Optional[List[str]] = None,
        interval: float = 1.0,
        send_timeout: float = 2.0,
    ):
        if not 0.01 <= interval <= 60 or not 0.01 <= send_timeout <= 60:
            raise ValueError("Bounded subscription timing required")

        self.journal = journal
        self.interval = interval
        self.send_timeout = send_timeout

        initial_groups = list(groups or [])
        if journal and hasattr(journal, "groups"):
            initial_groups.extend(journal.groups)
        if not initial_groups:
            initial_groups = ["robot_test@chatroom"]

        self.resources: Dict[str, str] = {
            f"wechat-core://events/{quote(g, safe='')}": g for g in initial_groups
        }
        self._sessions: Dict[int, Dict[str, Any]] = {}
        self._closed = False

    def group(self, uri: Union[str, AnyUrl]) -> str:
        """Resolve group identifier from URI."""
        value = str(uri)
        if value in self.resources:
            return self.resources[value]

        prefix = "wechat-core://events/"
        if value.startswith(prefix):
            grp = unquote(value[len(prefix) :])
            self.resources[value] = grp
            return grp

        raise ValueError("Resource outside configured event scope")

    async def read(self, uri: Union[str, AnyUrl]) -> Dict[str, Any]:
        """Read current resource head state."""
        group = self.group(uri)
        try:
            if self.journal and hasattr(self.journal, "head"):
                head = await asyncio.to_thread(self.journal.head, group)
            else:
                head = {
                    "group": group,
                    "change_token": "token_0",
                    "head_cursor": "0",
                }
        except Exception as error:
            return {
                "schema": SCHEMA,
                "group": group,
                "state": "unavailable",
                "error_type": type(error).__name__,
                "recovery": "query_persisted_cursor_without_automatic_reset",
            }

        return {
            **head,
            "schema": SCHEMA,
            "group": group,
            "state": "available",
            "transport": "mcp_resource_updated",
            "notifications": "coalesced_hints_not_delivery_acknowledgements",
            "resume": "wechat_core_events_from_persisted_processing_cursor",
        }

    async def _token(self, group: str) -> Tuple[str, str]:
        try:
            if self.journal and hasattr(self.journal, "head"):
                head = await asyncio.to_thread(self.journal.head, group)
                return ("available", head.get("change_token", "default"))
            return ("available", "static_token")
        except Exception as error:
            return ("unavailable", type(error).__name__)

    async def subscribe(self, session: Any, uri: Union[str, AnyUrl]) -> None:
        """Subscribe session to URI notifications."""
        group = self.group(uri)
        if self._closed:
            raise ValueError("Subscription manager is closed")

        value = str(uri)
        key = id(session)
        existing = self._sessions.get(key)
        if existing and value in existing["subscriptions"]:
            return

        token = await self._token(group)
        if self._closed:
            raise ValueError("Subscription manager is closed")

        state = self._sessions.get(key)
        if state is not None and value in state["subscriptions"]:
            return

        if state is None:
            state = {"session": session, "subscriptions": {}, "task": None}
            self._sessions[key] = state

        state["subscriptions"][value] = {"group": group, "token": token}
        if state["task"] is None:
            state["task"] = asyncio.create_task(self._run(key, state))

    async def unsubscribe(self, session: Any, uri: Union[str, AnyUrl]) -> None:
        """Unsubscribe session from URI notifications."""
        self.group(uri)
        key = id(session)
        state = self._sessions.get(key)
        if state is None:
            return

        state["subscriptions"].pop(str(uri), None)
        if not state["subscriptions"]:
            self._sessions.pop(key, None)
            if state["task"]:
                state["task"].cancel()
                with suppress(asyncio.CancelledError):
                    await state["task"]

    async def _run(self, key: int, state: Dict[str, Any]) -> None:
        try:
            while not self._closed and state["subscriptions"]:
                await asyncio.sleep(self.interval)
                for uri, subscription in list(state["subscriptions"].items()):
                    token = await self._token(subscription["group"])
                    if state["subscriptions"].get(uri) is not subscription:
                        continue
                    if token == subscription["token"]:
                        continue

                    try:
                        session = state["session"]
                        if hasattr(session, "send_resource_updated"):
                            await asyncio.wait_for(
                                session.send_resource_updated(AnyUrl(uri)),
                                timeout=self.send_timeout,
                            )
                    except asyncio.TimeoutError:
                        continue
                    except Exception:
                        return
                    subscription["token"] = token
        finally:
            if self._sessions.get(key) is state:
                self._sessions.pop(key, None)

    async def aclose(self) -> None:
        """Shut down all active push subscriptions."""
        self._closed = True
        tasks = [
            state["task"] for state in self._sessions.values() if state["task"]
        ]
        self._sessions.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def subscription_count(self) -> int:
        return sum(len(state["subscriptions"]) for state in self._sessions.values())


def install_event_push(
    server: Any,
    journal: Optional[Any] = None,
    interval: float = 1.0,
    send_timeout: float = 2.0,
) -> EventPush:
    """Attach standard resources/subscribe to the FastMCP server."""
    low = getattr(server, "_mcp_server", None)
    push = EventPush(journal=journal, interval=interval, send_timeout=send_timeout)

    for uri in list(push.resources.keys()):
        grp = push.group(uri)

        def _make_reader(res_uri: str):
            async def read_resource() -> str:
                return json.dumps(await push.read(res_uri), ensure_ascii=False)
            return read_resource

        try:
            server.resource(
                uri,
                name=f"WeChat events: {grp}",
                description="Subscribe for change hints, then replay wechat_core_events using saved cursor.",
                mime_type="application/json",
            )(_make_reader(uri))
        except Exception as e:
            logger.debug("Resource registration note: %s", e)

    if low and hasattr(low, "subscribe_resource"):
        @low.subscribe_resource()
        async def subscribe(uri: AnyUrl) -> None:
            session = getattr(low.request_context, "session", None)
            if session:
                await push.subscribe(session, uri)

        @low.unsubscribe_resource()
        async def unsubscribe(uri: AnyUrl) -> None:
            session = getattr(low.request_context, "session", None)
            if session:
                await push.unsubscribe(session, uri)

        if hasattr(low, "get_capabilities"):
            orig_caps = low.get_capabilities

            def capabilities(*args: Any, **kwargs: Any) -> Any:
                res = orig_caps(*args, **kwargs)
                if hasattr(res, "resources") and res.resources is not None:
                    res.resources.subscribe = True
                return res

            low.get_capabilities = capabilities

        if hasattr(low, "lifespan"):
            orig_lifespan = low.lifespan

            @asynccontextmanager
            async def lifespan(app: Any):
                try:
                    async with orig_lifespan(app) as ctx:
                        yield ctx
                finally:
                    await push.aclose()

            low.lifespan = lifespan

    server._wechat_event_push = push
    return push
