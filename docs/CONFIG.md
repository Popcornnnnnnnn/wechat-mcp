# Configuration, Client Setup & Troubleshooting

## Configuration Precedence

**Explicit CLI Flags > Environment Variables > JSON Config File > Auto-Discovery Defaults**

Copy [config.example.json](../config.example.json) to `~/.config/wechat-mcp/config.json` to customize defaults:

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

## Environment Variables

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
| `WECHAT_DEBOUNCE_INTERVAL_MS` | `500` | Kqueue file event debounce duration |
| `WECHAT_MAX_WATCHES` | `50` | Maximum file descriptors for kqueue |
| `WECHAT_RECALL_INTERVAL_SECONDS` | `3` | Anti-recall monitor polling interval |
| `WECHAT_RECALL_ARCHIVE_PATH` | `~/.local/share/wechat-mcp/recall-archive.sqlite` | SQLite file for preserved recalled messages |
| `WECHAT_SUMMARY_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint |
| `WECHAT_SUMMARY_API_KEY` | None | API key for summary pipeline |
| `WECHAT_SUMMARY_MODEL` | `gpt-4o-mini` | LLM model for link summaries |

## MCP Client Configurations

### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)
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

### Cursor (`.cursor/mcp.json`) & Antigravity (`~/.config/gemini/mcp_config.json`)
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

### SSE Remote Companion
```json
{
  "mcpServers": {
    "wechat-sse": {
      "url": "http://127.0.0.1:8301/sse"
    }
  }
}
```

## Troubleshooting & FAQ

- **`PermissionError: task_for_pid failed with kern_return_t=5`:** On WeChat 4.1/4.2, prefer `wechat-mcp keys --method lldb` (with `sudo DevToolsSecurity -enable`), or run `--method vm` with `sudo`.
- **`Operation not permitted` reading WeChat directory:** Grant **Full Disk Access** to your terminal, IDE, or Python runtime in **System Settings → Privacy & Security → Full Disk Access**.
- **`UnsafeLegacyCursor: Maximum server ID is not an incremental cursor`:** In WeChat 4.0+, `server_id` is not globally monotonic across shards. Legacy `since_id` is rejected; use cursor pagination (`wechat_core_messages`) or `wechat_core_events`.
- **`database is locked` during decryption:** `wechat-mcp` reads live WAL frames into memory snapshots; if contention persists, run `wechat-mcp sync --force`.
