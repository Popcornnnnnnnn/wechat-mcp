# FastMCP & REST API Reference

Full catalog of the 40 FastMCP tools, resource push protocol, and HTTP REST endpoints exposed by `wechat-mcp`.

## Core FastMCP Tools (30 Tools)

All tool outputs conform to `wechat.core.v1` envelopes (or redacted `wechat.core.error.v1` error envelopes).

| Tool Name | Parameters | Description | Output Schema |
|---|---|---|---|
| `wechat_core_health` | None | Reports overall service health, version, db availability, and queue states. | `wechat.core.v1` health dictionary |
| `wechat_core_sessions` | `limit: int = 100`, `offset: int = 0`, `refresh: bool = False` | Lists conversation sessions with message counts, last timestamp, and freshness. | `sessions: list[dict]`, `total`, `has_more` |
| `wechat_core_stats` | `refresh: bool = False` | Counts total chats, messages, contacts, shard count, and time bounds. | `chats`, `messages`, `contacts`, `shard_count` |
| `wechat_core_sync_history` | None | Refreshes snapshot reader without advancing event cursors. | `status: "synced"`, `refresh_performed: True` |
| `wechat_core_contacts` | `query: str = ""`, `limit: int = 50`, `refresh: bool = False`, `offset: int = 0` | Searches local contact directory by nickname, remark, or alias. | `contacts: list[dict]`, `total`, `has_more` |
| `wechat_core_group_members` | `group: str` (req), `limit: int = 100`, `offset: int = 0`, `refresh: bool = False` | Reads group member relationships for a group chatroom. | `group`, `members: list[dict]`, `total` |
| `wechat_core_messages` | `session: str` (req), `since: int = 0`, `until: int?`, `limit: int = 50`, `cursor: str?`, `refresh: bool = False`, `offset: int = 0` | Retrieves paged conversation messages with snapshot cursor pagination. | `messages: list[dict]`, `count`, `next_cursor` |
| `wechat_core_recalls` | `session: str?`, `since: int?`, `limit: int = 50`, `offset: int = 0`, `refresh: bool = True` | Lists withdrawn messages preserved by the anti-recall archive. | `recalls: list[dict]`, `total`, `freshness` |
| `wechat_core_recall_stats` | None | Summarizes recall coverage, indexed messages, tip vs diff counts. | `total`, `indexed_messages`, `tip`, `diff` |
| `wechat_core_search` | `query: str` (req), `session: str` (req), `since: int = 0`, `until: int?`, `limit: int = 20`, `refresh: bool = False`, `cursor: str?` | Searches decoded messages within a specific session window. | `results: list[dict]`, `matches`, `has_more` |
| `wechat_core_search_all` | `query: str` (req), `since: int = 0`, `until: int?`, `limit: int = 20`, `cursor: str?`, `refresh: bool = False` | Searches decoded messages across all authorized chat history. | `results: list[dict]`, `scanned`, `matches` |
| `wechat_core_moments` | `limit: int = 20`, `offset: int = 0`, `user: str?`, `since: int = 0`, `until: int?`, `refresh: bool = False` | Reads paged Moments posts from decrypted snapshot. | `posts: list[dict]`, `total`, `has_more` |
| `wechat_core_moments_search` | `query: str` (req), `limit: int = 20`, `offset: int = 0`, `user: str?`, `refresh: bool = False` | Searches Moments posts by text or author. | `posts: list[dict]`, `matches`, `has_more` |
| `wechat_core_moments_image_export` | `tid: int` (req), `media_id: str?`, `quality: str = "url"`, `refresh: bool = False` | Exports or decodes a Moments photo to disk. | `wechat.core.media.image-derivation.v1` |
| `wechat_core_moments_cache_export` | `limit: int = 10`, `refresh: bool = False` | Exports recently cached Moments images to disk. | `exported_files: list[str]`, `count` |
| `wechat_core_refresh` | None | Refreshes group history and discovery journal without sending. | `refreshed: True`, `new_events`, `status: "synced"` |
| `wechat_core_events` | `group: str` (req), `cursor: str?`, `limit: int = 100`, `refresh: bool = False` | Polls durable events from `EventJournal` with resumable cursor. | `wechat.core.events.v1`, `events: list`, `next_cursor` |
| `wechat_core_media_status` | `group: str` (req), `source_server_id: str` (req), `refresh: bool = False`, `verify_after_open: bool = False` | Resolves source-bound media local cache availability. | `media_bytes_available`, `acquisition_plan` |
| `wechat_core_media_inbox` | `session: str = ""`, `since: int = 0`, `until: int?`, `limit: int = 50`, `refresh: bool = False` | Lists media messages lacking verified local originals. | `items: list[dict]`, `total` |
| `wechat_core_download_original` | `session: str` (req), `source_server_id: str` (req) | Queues native request for original high-resolution image. | `operation_id`, `state: "queued"`, `session` |
| `wechat_core_media_operation` | `operation_id: str` (req), `refresh: bool = False` | Queries status of native media acquisition operation. | `operation_id`, `state`, `acquisition_verified` |
| `wechat_core_media_retention` | `session: str = ""`, `since: int = 0`, `until: int?`, `limit: int = 50`, `refresh: bool = False`, `retention_seconds: int = 604800` | Lists missing originals with expiration risk hints. | `items: list[dict]`, `total`, `expired` |
| `wechat_core_media_export` | `resource_id: str` (req), `session: str` (req), `source_server_id: str` (req), `refresh: bool = False` | Exports unchanged local media bytes to private directory. | `wechat.core.media.export.v1`, `sha256`, `size` |
| `wechat_core_audio_derive` | `resource_id: str` (req), `session: str` (req), `source_server_id: str` (req), `refresh: bool = False` | Decodes SILK audio to standard 16kHz WAV format. | `wechat.core.media.audio-derivation.v1`, `wav_path` |
| `wechat_core_image_derive` | `resource_id: str` (req), `session: str` (req), `source_server_id: str` (req), `refresh: bool = False` | Decodes XOR-encrypted V1/V2 DAT image to JPEG. | `wechat.core.media.image-derivation.v1`, `image_path` |
| `wechat_core_send_text` | `body: str` (req), `idempotency_key: str` (req), `target: str` (req) | Enqueues outbound message with idempotency key. | `idempotency_key`, `status: "queued"`, `target` |
| `wechat_core_reply_quote` | `body: str` (req), `idempotency_key: str` (req), `source_server_id: str` (req), `target: str` (req) | Enqueues quote reply referencing original server ID. | `idempotency_key`, `status: "queued"`, `source_server_id` |
| `wechat_core_operation_get` | `idempotency_key: str` (req) | Checks status of an outbound operation by idempotency key. | `idempotency_key`, `status`, `retry_unknown` |
| `wechat_core_reconcile` | `idempotency_key: str` (req), `refresh: bool = False`, `confirm: bool = False` | Reconciles local record against outbound ledger proof. | `idempotency_key`, `state_confirmed_from_local_proof` |
| `wechat_core_queue_control` | `paused: bool` (req) | Pauses or resumes outbound request queue. | `paused: bool`, `counts: {pending, processed}` |

## Legacy Alias Tools (10 Tools)

| Legacy Tool | Alias Target | Notes |
|---|---|---|
| `wechat_stats` | `wechat_core_stats` | Direct pass-through |
| `wechat_chats` | `wechat_core_sessions` | Direct pass-through |
| `wechat_messages` | `wechat_core_messages` | Rejects non-zero `since_id` with `UnsafeLegacyCursor` error |
| `wechat_search` | `wechat_core_search_all` | Query mapped to `q` parameter |
| `wechat_contacts` | `wechat_core_contacts` | Query mapped to `q` parameter |
| `wechat_sync` | `wechat_core_sync_history` | Direct pass-through |
| `wechat_moments` | `wechat_core_moments` | Direct pass-through |
| `wechat_moments_search` | `wechat_core_moments_search` | Direct pass-through |
| `wechat_moments_image_export` | `wechat_core_moments_image_export` | Direct pass-through |
| `wechat_moments_cache_export` | `wechat_core_moments_cache_export` | Direct pass-through |

## Resource Push Protocol

- **URI template:** `wechat-core://events/{group}`
- **Schema:** `wechat.core.event-resource.v1`
- Emits atomic notifications with updated `head_cursor` when `kqueue` detects database modifications.

## REST API Endpoints (`:8300`)

- `GET /api/stats` — Total chats, messages, and contact statistics.
- `GET /api/chats?limit=100&offset=0` — Paged chat session list with preview.
- `GET /api/chats/{username}/messages?limit=100&offset=0` — Conversation messages.
- `GET /api/contacts?q=&limit=50` — Local contacts directory search.
- `GET /api/search?q=&limit=20` — Full-text message search across all shards.
- `POST /api/sync` — Trigger on-demand WAL checkpoint and decryption.
