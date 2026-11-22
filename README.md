# wechat-mcp

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey)](https://www.apple.com/macos/)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP-40%20Tools-success)](https://modelcontextprotocol.io/)

Unified macOS WeChat Model Context Protocol (MCP) server, pure-Python SQLCipher 4 database decryptor, and multi-shard message query engine.

`wechat-mcp` unifies macOS WeChat database decryption, multi-shard history querying, FastMCP tooling, REST API serving, and anti-recall monitoring in a single package licensed under GNU General Public License v3.0 (GPL-3.0-or-later).

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Compatibility Matrix](#compatibility-matrix)
- [Prerequisites & Permissions](#prerequisites--permissions)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Mode 1: Database Key Extraction (`keys` & `info`)](#mode-1-database-key-extraction-keys--info)
  - [Mode 2: Shard Sync & Decryption (`sync` & `decrypt`)](#mode-2-shard-sync--decryption-sync--decrypt)
  - [Mode 3: FastMCP Server (`mcp`)](#mode-3-fastmcp-server-mcp)
  - [Mode 4: REST API Query Service (`api`)](#mode-4-rest-api-query-service-api)
  - [Mode 5: Anti-Recall Watcher (`recall`)](#mode-5-anti-recall-watcher-recall)
  - [Composite Mode (`serve`)](#composite-mode-serve)
- [MCP Client Configuration](#mcp-client-configuration)
  - [Claude Desktop](#1-claude-desktop)
  - [Cursor IDE](#2-cursor-ide)
  - [Gemini Code Assist / Antigravity](#3-gemini-code-assist--antigravity)
  - [SSE Remote Companion](#4-sse-remote-companion)
- [FastMCP Tool Reference (40 Tools)](#fastmcp-tool-reference-40-tools)
  - [Core Tools (30 Tools)](#core-tools-30-tools)
  - [Legacy Alias Tools (10 Tools)](#legacy-alias-tools-10-tools)
  - [Resource Push Protocol](#resource-push-protocol)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)

---

## Overview

Modern macOS WeChat stores chat histories across encrypted multi-shard SQLite databases using SQLCipher 4. `wechat-mcp` provides a fully automated pipeline to extract database encryption keys, decrypt SQLite shards without locking the WeChat process, and expose chat history, contacts, media, and real-time events to Large Language Models and external workflows via the standardized Model Context Protocol (MCP).

---

## Key Features

- **Automated Key Extraction**: Dynamic wxid discovery, Mach VM memory scanning for WeChat 4.0, and LLDB CommonCrypto register interception for WeChat 4.1/4.2.
- **Pure-Python SQLCipher 4 Engine**: AES-256-CBC decryption with PBKDF2-HMAC-SHA512 key derivation; zero C extensions or native SQLCipher compiler dependencies required.
- **Multi-Shard Query Engine**: SQLite `ATTACH` and `TEMP VIEW` union routing, Name2Id rowid mapping, and WCDB zstd/zlib payload decompression.
- **FastMCP 40-Tool Catalog**: 30 standard core tools (`wechat_core_*`) plus 10 backwards-compatible aliases (`wechat_*`), complete with structured `wechat.core.v1` schemas and recursive PII error redaction.
- **Durable Message Event Hooks**: Kqueue vnode file-system monitoring and persistent SQLite `EventJournal` with resumable cursors.
- **Dual-Signal Anti-Recall Watcher**: Real-time detection of withdrawn messages combining system revoke tips (`sysmsg`) and vanished message body diffing into a permanent `recall-archive.sqlite`.
- **FastAPI REST Service**: Native REST API listening on port 8300 for traditional intake scripts, webhooks, and local microservices.
- **Group Link Summary Pipeline**: Configurable 4-stage editorial pipeline producing structured JSON cards from group links.

---

## Architecture

```
+-----------------------------------------------------------------------------------+
|                                   wechat-mcp                                      |
+-----------------------------------------------------------------------------------+
|                                 CLI Entry Point                                   |
|       wechat-mcp [info | keys | sync | decrypt | mcp | api | recall | serve]        |
+--------------------------+----------------------------+---------------------------+
|      Crypto Layer        |       Database Layer       |       Watcher Layer       |
| - Mach VM Memory Scanner | - Multi-Shard Manager      | - Kqueue Vnode Monitor    |
| - LLDB CommonCrypto Hook | - Temp View UNIONS         | - SQLite EventJournal     |
| - Pure-Python SQLCipher4 | - Per-Shard Name2Id Map    | - Dual-Signal Anti-Recall |
| - 3-Tier WAL Checkpoint  | - WCDB zstd Decompression  | - Media Retention Ledger  |
+--------------------------+----------------------------+---------------------------+
|                               Server Interfaces                                   |
|  - FastMCP Server (40 Tools + SSE Resource Push "wechat-core://events/{group}")   |
|  - FastAPI REST Query Service (:8300)                                             |
|  - 4-Stage Group Link Summary Pipeline (Editorial JSON Cards)                     |
+-----------------------------------------------------------------------------------+
```

---

## Compatibility Matrix

| macOS WeChat Version | Key Extraction Technique | Module | Permissions & Requirements |
|---|---|---|---|
| **WeChat 4.0** | Mach VM Memory Scanning | `wechat_mcp.crypto.vm_scan` | Scans readable/writable memory chunks for `x'<key><salt>'`. Requires `task_for_pid` authorization (root or developer entitlements). |
| **WeChat 4.1 / 4.2** | LLDB CommonCrypto Breakpoint Hook | `wechat_mcp.crypto.lldb_keys` | Intercepts `CCCrypt`/`CCCryptorCreate` registers (`x3`/`x4` on Apple Silicon ARM64, `rcx`/`r8` on Intel x86_64). Validates key against Page 1 HMAC. |
| **All Versions** | Decryption & Querying | `wechat_mcp.crypto.decrypt` | Pure-Python SQLCipher 4 (AES-256-CBC, PBKDF2-HMAC-SHA512). Page size 4096, reserve 80 bytes. No native C dependencies. |

---

## Prerequisites & Permissions

Because macOS sandboxes third-party applications, the terminal or tool hosting `wechat-mcp` requires appropriate permissions.

### 1. Full Disk Access (FDA)
Required to read WeChat's sandbox storage container:
`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/`

**How to grant:**
1. Open **System Settings -> Privacy & Security -> Full Disk Access**.
2. Click `+` and add your terminal application (e.g., Terminal, iTerm2), your IDE (Cursor, VS Code), or the Python executable running the MCP server.
3. Ensure the toggle is switched **ON**.

### 2. Developer Tools Security (for LLDB Key Extraction)
Attaching LLDB to WeChat processes on macOS requires developer authorization:
```bash
sudo DevToolsSecurity -enable
sudo dscl . append /Groups/_developer GroupMembership $(whoami)
```
*Note on SIP*: WeChat does not carry restricted Apple internal entitlements, so key extraction attaches cleanly without disabling System Integrity Protection (SIP) when DevToolsSecurity is enabled.

---

## Installation

### Standard Installation
```bash
# Clone the repository
git clone https://github.com/Popcornnnnnnnn/wechat-mcp.git
cd wechat-mcp

# Install via pip
pip install .
```

### Editable Development Installation
```bash
# Install with development and test dependencies
pip install -e ".[dev]"

# Or using uv
uv pip install -e ".[dev]"
```

Verify installation:
```bash
wechat-mcp --version
wechat-mcp --help
```

---

## Quick Start

### Mode 1: Database Key Extraction (`keys` & `info`)

Inspect active accounts and extract SQLCipher database encryption keys:
```bash
# 1. Discover active WeChat account and storage paths
wechat-mcp info

# 2. Extract database keys automatically (auto-selects LLDB or Mach VM)
wechat-mcp keys --output ~/.config/wechat-mcp/keys.json

# 3. Explicit LLDB extraction with custom timeout
wechat-mcp keys --method lldb --timeout 60 --output ~/.config/wechat-mcp/keys.json
```

### Mode 2: Shard Sync & Decryption (`sync` & `decrypt`)

Checkpoint active WAL logs and decrypt all SQLite database shards:
```bash
# Synchronize and decrypt all shards for the active account
wechat-mcp sync

# Force sync all databases regardless of mtime
wechat-mcp sync --force

# Decrypt a specific single database manually
wechat-mcp decrypt path/to/message_0.db ./decrypted/message_0.db --key <64-hex-key>
```

### Mode 3: FastMCP Server (`mcp`)

Start the FastMCP server exposing all 40 tools:
```bash
# Standard I/O transport (used by Claude Desktop, Cursor, Antigravity)
wechat-mcp mcp --transport stdio

# SSE transport on port 8301
wechat-mcp mcp --transport sse --host 127.0.0.1 --port 8301
```

### Mode 4: REST API Query Service (`api`)

Launch the backwards-compatible REST service:
```bash
# Start REST API on 127.0.0.1:8300
wechat-mcp api

# Custom host and port
wechat-mcp api --host 0.0.0.0 --port 8300
```
Key REST endpoints:
- `GET /api/stats` - Total chats, messages, and contact statistics.
- `GET /api/chats?limit=100&offset=0` - Paged chat session list with preview.
- `GET /api/chats/{username}/messages?limit=100&offset=0` - Conversation messages.
- `GET /api/contacts?q=&limit=50` - Local contacts directory search.
- `GET /api/search?q=&limit=20` - Full-text message search across all shards.
- `POST /api/sync` - Trigger on-demand WAL checkpoint and decryption.

### Mode 5: Anti-Recall Watcher (`recall`)

Monitor messages in real-time or audit history for recalled messages:
```bash
# Continuous background monitoring with 2.0s interval
wechat-mcp recall --interval 2.0

# Single audit scan across all sessions
wechat-mcp recall --once

# Watch a specific chatroom or session only
wechat-mcp recall --session "demo_group@chatroom"
```

### Composite Mode (`serve`)

Run the REST API (port 8300) and FastMCP SSE (port 8301) simultaneously:
```bash
wechat-mcp serve --mode all --port 8300 --mcp-port 8301
```

---

## MCP Client Configuration

### 1. Claude Desktop
Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "wechat": {
      "command": "wechat-mcp",
      "args": ["mcp", "--transport", "stdio"],
      "env": {
        "WECHAT_DB_DIR": "/Users/USERNAME/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxxx/db_storage",
        "WECHAT_KEYS_FILE": "/Users/USERNAME/.config/wechat-mcp/keys.json",
        "WECHAT_DECRYPTED_DIR": "/Users/USERNAME/.local/share/wechat-mcp/decrypted"
      }
    }
  }
}
```

### 2. Cursor IDE
Add to `.cursor/mcp.json` or your Cursor global MCP settings:
```json
{
  "mcpServers": {
    "wechat": {
      "command": "wechat-mcp",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

### 3. Gemini Code Assist / Antigravity
Add to `~/.config/gemini/mcp_config.json`:
```json
{
  "mcpServers": {
    "wechat": {
      "command": "wechat-mcp",
      "args": ["mcp", "--transport", "stdio"]
    }
  }
}
```

### 4. SSE Remote Companion
For agents or companion scripts connecting over Server-Sent Events (SSE):
```json
{
  "mcpServers": {
    "wechat-sse": {
      "url": "http://127.0.0.1:8301/sse"
    }
  }
}
```

---

## FastMCP Tool Reference (40 Tools)

`wechat-mcp` exposes 40 tools: 30 core tools (`wechat_core_*`) with comprehensive schemas, and 10 legacy alias tools (`wechat_*`) for backwards compatibility. All tool outputs conform to structured envelopes (`wechat.core.v1` or safe error envelope `wechat.core.error.v1`).

### Core Tools (30 Tools)

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
| `wechat_core_moments` | `limit: int = 20`, `offset: int = 0`, `user: str?`, `since: int = 0`, `until: int?`, `refresh: bool = False` | Reads paged Moments (朋友圈) posts from decrypted snapshot. | `posts: list[dict]`, `total`, `has_more` |
| `wechat_core_moments_search` | `query: str` (req), `limit: int = 20`, `offset: int = 0`, `user: str?`, `refresh: bool = False` | Searches Moments posts by text or author. | `posts: list[dict]`, `matches`, `has_more` |
| `wechat_core_moments_image_export` | `tid: int` (req), `media_id: str?`, `quality: str = "url"`, `refresh: bool = False` | Exports or decodes a Moments photo to disk. | `wechat.core.media.image-derivation.v1` |
| `wechat_core_moments_cache_export` | `limit: int = 10`, `refresh: bool = False` | Exports recently cached Moments images to disk. | `exported_files: list[str]`, `count` |
| `wechat_core_refresh` | None | Refreshes group history and discovery journal without sending. | `refreshed: True`, `new_events`, `status: "synced"` |
| `wechat_core_events` | `group: str` (req), `cursor: str?`, `limit: int = 100`, `refresh: bool = False` | Polls durable events from EventJournal with resumable cursor. | `wechat.core.events.v1`, `events: list`, `next_cursor` |
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

### Legacy Alias Tools (10 Tools)

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

### Resource Push Protocol
`wechat-mcp` exposes real-time subscribable MCP resources:
- URI template: `wechat-core://events/{group}`
- Schema: `wechat.core.event-resource.v1`
- Emits atomic event notifications with updated `head_cursor` when kqueue detects database modifications.

---

## Configuration Reference

`wechat-mcp` follows strict configuration precedence:
**Explicit CLI Flags > Environment Variables > JSON Config File > Auto-Discovery Defaults**

Copy `config.example.json` to `~/.config/wechat-mcp/config.json` to customize defaults:

```json
{
  "wxid": "",
  "db_dir": "",
  "decrypted_dir": "~/.local/share/wechat-mcp/decrypted",
  "keys_file": "~/.config/wechat-mcp/keys.json",
  "decoded_image_dir": "~/.local/share/wechat-mcp/decoded_images",
  "runtime_dir": "~/.local/share/wechat-mcp/runtime",
  "sqlcipher_bin": null,
  "api_host": "127.0.0.1",
  "api_port": 8300,
  "mcp_transport": "stdio",
  "mcp_port": 8301,
  "sync_interval_seconds": 20,
  "log_level": "INFO",
  "debounce_interval_ms": 500,
  "max_watches": 50,
  "recall_interval_seconds": 3,
  "recall_archive_path": "~/.local/share/wechat-mcp/recall-archive.sqlite",
  "summary_base_url": "https://api.openai.com/v1",
  "summary_api_key": null,
  "summary_model": "gpt-4o-mini",
  "summary_default_tone": "analytical",
  "summary_default_template": "quick_brief",
  "summary_timeout_seconds": 30
}
```

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `WECHAT_CONFIG_FILE` | `~/.config/wechat-mcp/config.json` | Path to JSON config file |
| `WECHAT_DB_DIR` | Auto-discovered | Path to WeChat `db_storage` folder |
| `WECHAT_KEYS_FILE` | `~/.config/wechat-mcp/keys.json` | Path to extracted encryption keys |
| `WECHAT_DECRYPTED_DIR` | `~/.local/share/wechat-mcp/decrypted` | Path for decrypted SQLite shards |
| `WECHAT_API_HOST` | `127.0.0.1` | REST API bind host |
| `WECHAT_API_PORT` | `8300` | REST API bind port |
| `WECHAT_SYNC_INTERVAL` | `20` | Interval in seconds between WAL checks |
| `WECHAT_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `WECHAT_DEBOUNCE_INTERVAL_MS`| `500` | Kqueue file event debounce duration |
| `WECHAT_MAX_WATCHES` | `50` | Maximum file descriptors for kqueue |
| `WECHAT_RECALL_INTERVAL_SECONDS`| `3` | Anti-recall monitor polling interval |
| `WECHAT_RECALL_ARCHIVE_PATH` | `~/.local/share/wechat-mcp/recall-archive.sqlite` | SQLite file for preserved recalled messages |
| `WECHAT_SUMMARY_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `WECHAT_SUMMARY_API_KEY` | None | API key for summary pipeline |
| `WECHAT_SUMMARY_MODEL` | `gpt-4o-mini` | LLM model for link summaries |

---

## Troubleshooting & FAQ

### Q: `PermissionError: task_for_pid failed with kern_return_t=5`
**Resolution**:
- If using `wechat-mcp keys --method vm`, `task_for_pid` requires root or Developer privileges. Run with `sudo wechat-mcp keys --method vm` or use `wechat-mcp keys --method lldb` which attaches via standard macOS debugging privileges (`DevToolsSecurity -enable`).

### Q: `Operation not permitted` reading WeChat directory
**Resolution**:
- The running application does not have Full Disk Access. Grant Full Disk Access to your terminal or IDE in **System Settings -> Privacy & Security -> Full Disk Access**.

### Q: `UnsafeLegacyCursor: Maximum server ID is not an incremental cursor`
**Resolution**:
- In WeChat 4.0+, multi-shard databases do not have globally monotonic `server_id` counters across shards. The legacy `since_id` parameter is intentionally rejected to prevent lost messages. Use `cursor` snapshot pagination or poll `wechat_core_events`.

### Q: `database is locked` during decryption
**Resolution**:
- `wechat-mcp` automatically avoids locking live databases by reading WAL frames into an in-memory snapshot before decrypting. If this persists, trigger a checkpoint via `wechat-mcp sync --force`.

---

## License

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version**.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](LICENSE) for more details.

Copyright (C) 2026 wechat-mcp contributors.
