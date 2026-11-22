# wechat-mcp

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python: >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Platform: macOS](https://img.shields.io/badge/platform-macOS-lightgrey)](https://www.apple.com/macos/)
[![FastMCP Tools](https://img.shields.io/badge/FastMCP-40%20Tools-success)](https://modelcontextprotocol.io/)

[English](README.md) | **简体中文**

面向 macOS 微信（4.0 / 4.1 / 4.2）的统一 Model Context Protocol (MCP) 服务、纯 Python SQLCipher 4 数据库解密器与多分片聊天记录检索引擎。

`wechat-mcp` 将 macOS 微信密钥提取、数据库解密与 WAL 快照同步、多分片查询、FastMCP 工具集、REST API（`:8300`）、防撤回监听及群聊链接摘要管线整合为一体，采用 **GNU General Public License v3.0 (GPL-3.0-or-later)** 开源协议。

---

## 目录

- [简介](#简介)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [版本兼容矩阵](#版本兼容矩阵)
- [前置权限要求](#前置权限要求)
- [安装步骤](#安装步骤)
- [快速开始](#快速开始)
  - [1. 提取数据库密钥（keys 与 info）](#1-提取数据库密钥keys-与-info)
  - [2. 分片同步与解密（sync 与 decrypt）](#2-分片同步与解密sync-与-decrypt)
  - [3. 启动 FastMCP 服务（mcp）](#3-启动-fastmcp-服务mcp)
  - [4. 启动 REST API 服务（api）](#4-启动-rest-api-服务api)
  - [5. 运行防撤回监控（recall）](#5-运行防撤回监控recall)
  - [6. 组合启动模式（serve）](#6-组合启动模式serve)
- [MCP 客户端接入配置](#mcp-客户端接入配置)
- [FastMCP 工具全览（共 40 个工具）](#fastmcp-工具全览共-40-个工具)
- [配置项与环境变量说明](#配置项与环境变量说明)
- [常见问题排查（FAQ）](#常见问题排查faq)
- [开源协议](#开源协议)

---

## 简介

现代 macOS 版微信（4.0+）使用基于 SQLCipher 4 加密的 WCDB 多分片 SQLite 数据库存储本地聊天记录、联系人、会话和朋友圈缓存。`wechat-mcp` 提供完全自动化、不锁死微信主进程的本地流水线：自动提取密钥、以只读快照方式解密全部分片数据库，并通过标准 MCP 协议与本地 HTTP REST API 向 Claude Desktop、Cursor、Antigravity、Codex 等 AI Agent 安全暴露历史消息、联系人、媒体解密与实时事件流。

---

## 核心特性

- **自动化密钥提取**：自动探测当前微信 `wxid` 与沙盒目录；支持 WeChat 4.0 Mach VM 内存扫描，以及 WeChat 4.1 / 4.2 免关闭 SIP 的 LLDB CommonCrypto 寄存器断点抓取。
- **纯 Python SQLCipher 4 解密引擎**：内置 AES-256-CBC + PBKDF2-HMAC-SHA512 解密实现，零原生 C 扩展或外部 `sqlcipher` 编译依赖。
- **多分片联合查询引擎**：通过 SQLite `ATTACH` 与 `TEMP VIEW` 跨 `message_*.db` 自动路由查询，自动处理每个分片独立的 `Name2Id` 映射与 WCDB zstd/zlib 压缩载荷解压。
- **40 个 FastMCP 标准工具**：包含 30 个标准化核心工具（`wechat_core_*`）与 10 个向后兼容别名（`wechat_*`），采用统一输出信封（`wechat.core.v1`）与递归路径/`wxid` 脱敏错误信封（`wechat.core.error.v1`）。
- **Kqueue 实时监听与事件日志**：基于 macOS `kqueue` vnode 监听数据库变化，写入可断点续传的 SQLite `EventJournal`，并支持 MCP Resource 订阅推送（`wechat-core://events/{group}`）。
- **双信号防撤回归档**：结合系统撤回提示（`sysmsg`）与消息体消失对比（diff），实时留存撤回内容至 `recall-archive.sqlite`。
- **REST API 查询服务（`:8300`）**：便于本地脚本、守护进程、自动化工作流（如 Watchpost 外部插件）直接通过 HTTP 调用。
- **群聊链接 4 阶段摘要管线**：自动抽取并生成结构化文章摘要 JSON 卡片。

---

## 系统架构

```
+-----------------------------------------------------------------------------------+
|                                   wechat-mcp                                      |
+-----------------------------------------------------------------------------------+
|                                    CLI 入口                                        |
|       wechat-mcp [info | keys | sync | decrypt | mcp | api | recall | serve]        |
+--------------------------+----------------------------+---------------------------+
|      加密与同步层         |         数据库查询层         |        事件与防撤回层       |
| - Mach VM 内存扫描        | - 多分片联合查询路由          | - Kqueue Vnode 文件监听    |
| - LLDB CommonCrypto Hook | - 跨分片 TEMP VIEW UNION      | - SQLite EventJournal     |
| - 纯 Python SQLCipher 4  | - 分片独立 Name2Id 映射       | - 双信号防撤回归档          |
| - 三级 WAL 快照复制       | - WCDB zstd/zlib 自动解压     | - 媒体保留与解密校验        |
+--------------------------+----------------------------+---------------------------+
|                                    服务输出接口                                     |
|  - FastMCP Server（40 工具 + SSE 资源推送 "wechat-core://events/{group}"）          |
|  - FastAPI REST Query Service（默认监听 127.0.0.1:8300）                            |
+-----------------------------------------------------------------------------------+
```

---

## 版本兼容矩阵

| macOS 微信版本 | 密钥提取机制 | 核心模块 | 所需权限与说明 |
|---|---|---|---|
| **WeChat 4.0** | Mach VM 内存扫描 | `wechat_mcp.crypto.vm_scan` | 扫描可读写内存中的 `x'<key><salt>'` 模式，需 `task_for_pid` 权限（`sudo` 或开发者权限）。 |
| **WeChat 4.1 / 4.2** | LLDB CommonCrypto 断点捕获 | `wechat_mcp.crypto.lldb_keys` | 拦截 `CCCrypt` / `CCCryptorCreate` 寄存器（Apple Silicon ARM64 读取 `x3`/`x4`，Intel 读取 `rcx`/`r8`），并校验 Page 1 HMAC。 |
| **全版本通用** | SQLCipher 4 解密与查询 | `wechat_mcp.crypto.decrypt` | 纯 Python 实现（AES-256-CBC，页大小 4096，保留字节 80）。 |

---

## 前置权限要求

由于 macOS 沙盒与调试安全限制，运行 `wechat-mcp` 的终端或宿主应用需要以下授权：

### 1. 完全磁盘访问权限（Full Disk Access）
用于读取微信沙盒存储目录：
`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/`

配置步骤：
1. 打开 **系统设置 -> 隐私与安全性 -> 完全磁盘访问权限**。
2. 点击 `+` 添加你正在使用的终端（Terminal、iTerm2、Warp 等）或运行 MCP 的 Python/IDE。
3. 开启右侧开关。

### 2. 开发者工具权限（用于 LLDB 提取密钥）
允许 LLDB 附加到已签名的微信进程（无需关闭 macOS SIP）：
```bash
sudo DevToolsSecurity -enable
sudo dscl . append /Groups/_developer GroupMembership $(whoami)
```

---

## 安装步骤

```bash
# 克隆仓库
git clone https://github.com/Popcornnnnnnnn/wechat-mcp.git
cd wechat-mcp

# 标准安装
pip install .

# 或使用 uv 安装（含开发与测试依赖）
uv pip install -e ".[dev]"
```

验证安装是否成功：
```bash
wechat-mcp --version
wechat-mcp --help
```

---

## 快速开始

### 1. 提取数据库密钥（`keys` 与 `info`）

```bash
# 1. 自动识别当前登录账号与数据库存储路径
wechat-mcp info

# 2. 提取 SQLCipher 密钥（默认自动选择 LLDB 或 Mach VM）
wechat-mcp keys --output ~/.config/wechat-mcp/keys.json

# 3. 显式指定 LLDB 方式并设置超时
wechat-mcp keys --method lldb --timeout 60 --output ~/.config/wechat-mcp/keys.json
```

### 2. 分片同步与解密（`sync` 与 `decrypt`）

安全复制实时 WAL 与数据库快照，并逐个分片解密到独立目录（不锁死正在运行的微信）：
```bash
# 增量同步并解密所有分片
wechat-mcp sync

# 忽略 mtime 强制全量重解
wechat-mcp sync --force

# 手动解密单个数据库分片
wechat-mcp decrypt path/to/message_0.db ./decrypted/message_0.db --key <64位十六进制密钥>
```

### 3. 启动 FastMCP 服务（`mcp`）

```bash
# 标准输入输出模式（供 Claude Desktop / Cursor / Antigravity / Codex 调用）
wechat-mcp mcp --transport stdio

# SSE 模式（监听 127.0.0.1:8301）
wechat-mcp mcp --transport sse --host 127.0.0.1 --port 8301
```

### 4. 启动 REST API 服务（`api`）

```bash
# 默认启动在 127.0.0.1:8300
wechat-mcp api

# 自定义绑定地址与端口
wechat-mcp api --host 127.0.0.1 --port 8300
```

常用 REST 接口：
- `GET /api/stats`：统计会话数、消息数与联系人总数
- `GET /api/chats?limit=100&offset=0`：分页获取会话列表与最新预览
- `GET /api/chats/{username}/messages?limit=100&offset=0`：查询指定会话历史消息
- `GET /api/contacts?q=&limit=50`：搜索联系人（昵称、备注、微信号）
- `GET /api/search?q=&limit=20`：跨全部分片搜索聊天文本
- `POST /api/sync`：按需触发 WAL 检查点并同步解密最新分片

### 5. 运行防撤回监控（`recall`）

```bash
# 持续后台监测（每 2 秒检查）
wechat-mcp recall --interval 2.0

# 单次全库审计扫描
wechat-mcp recall --once

# 仅监控指定群聊或会话
wechat-mcp recall --session "demo_group@chatroom"
```

### 6. 组合启动模式（`serve`）

同时启动 REST API（`:8300`）与 FastMCP SSE（`:8301`）：
```bash
wechat-mcp serve --mode all --port 8300 --mcp-port 8301
```

---

## MCP 客户端接入配置

### Claude Desktop / 通用 stdio 客户端
将以下配置写入客户端配置文件（请将 `USERNAME` 替换为你的 macOS 用户名）：
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

### SSE 远程调用模式
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

## FastMCP 工具全览（共 40 个工具）

`wechat-mcp` 提供 30 个规范化核心工具（`wechat_core_*`）及 10 个向后兼容别名工具（`wechat_*`），完整参数与输出结构可参见英文文档 [README.md](README.md#fastmcp-tool-reference-40-tools)：

- **健康与会话查询**：`wechat_core_health`、`wechat_core_sessions`、`wechat_core_stats`、`wechat_core_sync_history`、`wechat_core_contacts`、`wechat_core_group_members`
- **消息与全文检索**：`wechat_core_messages`（支持游标分页）、`wechat_core_search`、`wechat_core_search_all`、`wechat_core_recalls`、`wechat_core_recall_stats`
- **朋友圈检索与导出**：`wechat_core_moments`、`wechat_core_moments_search`、`wechat_core_moments_image_export`、`wechat_core_moments_cache_export`
- **事件流与增量同步**：`wechat_core_refresh`、`wechat_core_events`（搭配 `wechat-core://events/{group}` SSE 资源订阅）
- **媒体状态与本地导出/解码**：`wechat_core_media_status`、`wechat_core_media_inbox`、`wechat_core_download_original`、`wechat_core_media_operation`、`wechat_core_media_retention`、`wechat_core_media_export`、`wechat_core_audio_derive`、`wechat_core_image_derive`
- **出站发送队列与核对账本**：`wechat_core_send_text`、`wechat_core_reply_quote`、`wechat_core_operation_get`、`wechat_core_reconcile`、`wechat_core_queue_control`
- **向后兼容别名（10 个）**：`wechat_stats`、`wechat_chats`、`wechat_messages`、`wechat_search`、`wechat_contacts`、`wechat_sync`、`wechat_moments`、`wechat_moments_search`、`wechat_moments_image_export`、`wechat_moments_cache_export`

---

## 配置项与环境变量说明

配置优先级由高到低为：**CLI 显式参数 > 环境变量 > JSON 配置文件 > 自动探测默认值**。

可复制 [config.example.json](config.example.json) 到 `~/.config/wechat-mcp/config.json` 后按需修改：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WECHAT_CONFIG_FILE` | `~/.config/wechat-mcp/config.json` | JSON 配置文件路径 |
| `WECHAT_DB_DIR` | 自动探测 | 微信 `db_storage` 目录路径 |
| `WECHAT_KEYS_FILE` | `~/.config/wechat-mcp/keys.json` | 密钥文件路径 |
| `WECHAT_DECRYPTED_DIR` | `~/.local/share/wechat-mcp/decrypted` | 解密后 SQLite 分片存放目录 |
| `WECHAT_API_HOST` | `127.0.0.1` | REST API 监听地址 |
| `WECHAT_API_PORT` | `8300` | REST API 监听端口 |
| `WECHAT_SYNC_INTERVAL` | `20` | WAL 检查与同步间隔（秒） |
| `WECHAT_LOG_LEVEL` | `INFO` | 日志级别（`DEBUG`/`INFO`/`WARNING`/`ERROR`） |
| `WECHAT_RECALL_INTERVAL_SECONDS` | `3` | 防撤回扫描间隔（秒） |
| `WECHAT_RECALL_ARCHIVE_PATH` | `~/.local/share/wechat-mcp/recall-archive.sqlite` | 撤回记录归档库路径 |
| `WECHAT_SUMMARY_BASE_URL` | `https://api.openai.com/v1` | 摘要管线 OpenAI 兼容接口地址 |
| `WECHAT_SUMMARY_API_KEY` | `None` | 摘要管线 API Key |
| `WECHAT_SUMMARY_MODEL` | `gpt-4o-mini` | 摘要管线默认模型 |

---

## 常见问题排查（FAQ）

- **`PermissionError: task_for_pid failed with kern_return_t=5`**：WeChat 4.1/4.2 请优先使用 `wechat-mcp keys --method lldb`（需先开启 `sudo DevToolsSecurity -enable`）；若使用 `--method vm`，需配合 `sudo`。
- **`Operation not permitted` 读取微信目录失败**：请检查运行终端或宿主 IDE 是否已在系统设置中授予“完全磁盘访问权限”。
- **`UnsafeLegacyCursor` 报错**：WeChat 4.0+ 多分片库中 `server_id` 并非全局严格递增，旧版 `wechat_messages` 的 `since_id` 已被禁止；请改用游标分页或 `wechat_core_events`。
- **提示 `database is locked`**：`wechat-mcp` 默认对实时库与 `-wal` 做快照拷贝后离线解密；若偶发锁冲突，可执行 `wechat-mcp sync --force` 刷新快照。

---

## 开源协议

本项目基于 **GNU General Public License v3.0 or later (GPL-3.0-or-later)** 许可协议开源。详情请参阅 [LICENSE](LICENSE)。
