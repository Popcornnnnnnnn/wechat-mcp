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

"""Dynamic configuration and path discovery for wechat-mcp."""
from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class WeChatConfigError(Exception):
    """Raised when WeChat data paths or configuration cannot be resolved."""
    pass


ConfigurationError = WeChatConfigError


@dataclass
class AccountInfo:
    """Information about a detected WeChat account directory."""
    wxid: str
    account_dir: Path
    db_storage_dir: Path
    last_active_time: float
    is_active: bool = False


@dataclass
class Config:
    """Consolidated configuration for wechat-mcp."""
    db_dir: Path
    wechat_base_dir: Path
    keys_file: Path
    decrypted_dir: Path
    decoded_image_dir: Path
    runtime_dir: Path
    wxid: str
    api_host: str = "127.0.0.1"
    api_port: int = 8300
    sync_interval_seconds: int = 20
    log_level: str = "INFO"
    sqlcipher_bin: Optional[Path] = None
    config_file: Optional[Path] = None
    # Watcher debounce settings
    debounce_interval_ms: int = 500
    max_watches: int = 50
    # Anti-recall watcher settings
    recall_interval_seconds: int = 3
    recall_archive_path: Optional[Path] = None
    # Summary pipeline settings
    summary_base_url: str = "https://api.openai.com/v1"
    summary_api_key: Optional[str] = None
    summary_model: str = "gpt-4o-mini"
    summary_default_tone: str = "analytical"
    summary_default_template: str = "quick_brief"
    summary_timeout_seconds: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_dir": str(self.db_dir),
            "wechat_base_dir": str(self.wechat_base_dir),
            "keys_file": str(self.keys_file),
            "decrypted_dir": str(self.decrypted_dir),
            "decoded_image_dir": str(self.decoded_image_dir),
            "runtime_dir": str(self.runtime_dir),
            "wxid": self.wxid,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "sync_interval_seconds": self.sync_interval_seconds,
            "log_level": self.log_level,
            "sqlcipher_bin": str(self.sqlcipher_bin) if self.sqlcipher_bin else None,
            "config_file": str(self.config_file) if self.config_file else None,
            "debounce_interval_ms": self.debounce_interval_ms,
            "max_watches": self.max_watches,
            "recall_interval_seconds": self.recall_interval_seconds,
            "recall_archive_path": str(self.recall_archive_path) if self.recall_archive_path else None,
            "summary_base_url": self.summary_base_url,
            "summary_api_key": self.summary_api_key,
            "summary_model": self.summary_model,
            "summary_default_tone": self.summary_default_tone,
            "summary_default_template": self.summary_default_template,
            "summary_timeout_seconds": self.summary_timeout_seconds,
        }

    @classmethod
    def load(
        cls,
        config_file: Optional[Union[Path, str]] = None,
        db_dir: Optional[Union[Path, str]] = None,
        wxid: Optional[str] = None,
        keys_file: Optional[Union[Path, str]] = None,
        decrypted_dir: Optional[Union[Path, str]] = None,
    ) -> Config:
        return load_config(
            config_file=config_file,
            db_dir=db_dir,
            wxid=wxid,
            keys_file=keys_file,
            decrypted_dir=decrypted_dir,
        )


WeChatConfig = Config


def get_user_home() -> Path:
    """Resolve user home directory respecting SUDO_USER if running under root."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        if sys.platform == "darwin":
            candidate = Path(f"/Users/{sudo_user}")
            if candidate.is_dir():
                return candidate
        elif sys.platform.startswith("linux"):
            candidate = Path(f"/home/{sudo_user}")
            if candidate.is_dir():
                return candidate
    return Path.home()


def find_sqlcipher_binary() -> Optional[Path]:
    """Locate the sqlcipher CLI binary across common macOS and Linux locations."""
    # 1. Environment variable override
    env_bin = os.environ.get("SQLCIPHER_PATH") or os.environ.get("WECHAT_SQLCIPHER_PATH")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return Path(env_bin).resolve()

    # 2. PATH resolution
    which_bin = shutil.which("sqlcipher")
    if which_bin:
        return Path(which_bin).resolve()

    # 3. Known platform locations
    candidates = [
        Path("/opt/homebrew/bin/sqlcipher"),       # macOS Apple Silicon
        Path("/usr/local/bin/sqlcipher"),          # macOS Intel / Homebrew
        Path("/usr/bin/sqlcipher"),                # Linux standard
        Path("/usr/local/opt/sqlcipher/bin/sqlcipher"),
        Path("/opt/homebrew/opt/sqlcipher/bin/sqlcipher"),
    ]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return p.resolve()
    return None


def get_search_roots() -> List[Path]:
    """Return platform candidate directories containing WeChat user data."""
    home = get_user_home()
    roots = []
    if sys.platform == "darwin":
        roots.append(home / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files")
        roots.append(home / "Documents/xwechat_files")
    elif sys.platform.startswith("linux"):
        roots.append(home / "Documents/xwechat_files")
        roots.append(home / ".local/share/weixin/data")
    else:
        appdata = os.environ.get("APPDATA")
        if appdata:
            roots.append(Path(appdata) / "Tencent/xwechat/xwechat_files")
    return [r for r in roots if r.exists()]


def discover_accounts() -> List[AccountInfo]:
    """Scan search roots and return all detected WeChat accounts sorted by activity."""
    accounts: List[AccountInfo] = []
    ignored = {"all_users", "Backup", "temp", "crash", ".DS_Store"}

    for root in get_search_roots():
        if not root.is_dir():
            continue
        try:
            for entry in root.iterdir():
                if entry.name in ignored or not entry.is_dir():
                    continue
                db_storage = entry / "db_storage"
                if db_storage.is_dir():
                    # Activity timestamp: check message dir mtime, fallback to db_storage
                    msg_dir = db_storage / "message"
                    target = msg_dir if msg_dir.is_dir() else db_storage
                    try:
                        mtime = target.stat().st_mtime
                    except OSError:
                        mtime = 0.0

                    accounts.append(AccountInfo(
                        wxid=entry.name,
                        account_dir=entry.resolve(),
                        db_storage_dir=db_storage.resolve(),
                        last_active_time=mtime,
                    ))
        except (PermissionError, OSError):
            continue

    # Sort descending by last active time (most recent first)
    accounts.sort(key=lambda a: a.last_active_time, reverse=True)
    if accounts:
        accounts[0].is_active = True
    return accounts


def discover_wechat_accounts() -> List[Path]:
    """Return account directory paths for all discovered WeChat accounts."""
    return [a.account_dir for a in discover_accounts()]


def get_active_db_storage() -> Optional[Path]:
    """Find the most recently active db_storage directory."""
    accounts = discover_accounts()
    if accounts:
        return accounts[0].db_storage_dir
    return None


def discover_wechat_db_dir() -> Optional[Path]:
    """Discover WeChat db_storage path automatically."""
    return get_active_db_storage()


def load_config(
    config_file: Optional[Union[Path, str]] = None,
    db_dir: Optional[Union[Path, str]] = None,
    wxid: Optional[str] = None,
    keys_file: Optional[Union[Path, str]] = None,
    decrypted_dir: Optional[Union[Path, str]] = None,
) -> Config:
    """Load configuration with full precedence hierarchy: args > env > file > discovery."""
    home = get_user_home()
    default_config_file = home / ".config/wechat-mcp/config.json"
    target_config = Path(config_file or os.environ.get("WECHAT_CONFIG_FILE", default_config_file)).expanduser()

    json_cfg: Dict[str, Any] = {}
    if target_config.is_file():
        try:
            with open(target_config, "r", encoding="utf-8") as f:
                json_cfg = json.load(f)
        except Exception:
            pass

    resolved_db_dir: Optional[Path] = None
    resolved_wxid: str = ""

    # 1. Direct param or Env var WECHAT_DB_DIR or config file
    # Precedence: explicit db_dir/WECHAT_DB_DIR > explicit wxid/WECHAT_WXID > file db_dir > file wxid > discovery
    explicit_db = db_dir or os.environ.get("WECHAT_DB_DIR")
    explicit_wxid = wxid or os.environ.get("WECHAT_WXID")
    env_db = explicit_db or (None if explicit_wxid else json_cfg.get("db_dir"))
    if env_db:
        p = Path(env_db).expanduser().resolve()
        if p.name == "db_storage":
            resolved_db_dir = p
            resolved_wxid = p.parent.name
        elif (p / "db_storage").is_dir():
            resolved_db_dir = p / "db_storage"
            resolved_wxid = p.name
        else:
            resolved_db_dir = p
            resolved_wxid = p.parent.name

    # 2. If not directly set, discover accounts
    if not resolved_db_dir:
        target_wxid = wxid or os.environ.get("WECHAT_WXID") or json_cfg.get("wxid")
        accounts = discover_accounts()
        if not accounts:
            raise WeChatConfigError(
                "No WeChat accounts found. Ensure WeChat is installed and logged in, "
                "or specify WECHAT_DB_DIR manually."
            )
        if target_wxid:
            matched = [a for a in accounts if a.wxid == target_wxid]
            if not matched:
                raise WeChatConfigError(f"Specified WeChat account wxid '{target_wxid}' not found.")
            account = matched[0]
        else:
            account = accounts[0]  # Most active account

        resolved_db_dir = account.db_storage_dir
        resolved_wxid = account.wxid

    resolved_base_dir = resolved_db_dir.parent

    # Resolve keys_file
    default_keys = home / ".config/wechat-mcp/keys.json"
    env_keys = keys_file or os.environ.get("WECHAT_KEYS_FILE") or json_cfg.get("keys_file")
    resolved_keys = Path(env_keys or default_keys).expanduser().resolve()

    # Resolve decrypted_dir
    default_dec = home / ".local/share/wechat-mcp/decrypted"
    env_dec = decrypted_dir or os.environ.get("WECHAT_DECRYPTED_DIR") or json_cfg.get("decrypted_dir")
    resolved_dec = Path(env_dec or default_dec).expanduser().resolve()

    # Runtime and image dirs
    default_img = home / ".local/share/wechat-mcp/decoded_images"
    env_img = os.environ.get("WECHAT_DECODED_IMAGE_DIR") or json_cfg.get("decoded_image_dir")
    resolved_img = Path(env_img or default_img).expanduser().resolve()

    default_runtime = home / ".local/share/wechat-mcp/runtime"
    env_runtime = os.environ.get("WECHAT_RUNTIME_DIR") or json_cfg.get("runtime_dir")
    resolved_runtime = Path(env_runtime or default_runtime).expanduser().resolve()

    # API options
    api_host = os.environ.get("WECHAT_API_HOST") or json_cfg.get("api_host", "127.0.0.1")
    api_port_val = os.environ.get("WECHAT_API_PORT") or json_cfg.get("api_port", 8300)
    api_port = int(api_port_val)

    sync_interval = int(os.environ.get("WECHAT_SYNC_INTERVAL") or os.environ.get("WECHAT_SYNC_INTERVAL_SECONDS") or json_cfg.get("sync_interval_seconds", 20))
    log_level = os.environ.get("WECHAT_LOG_LEVEL") or json_cfg.get("log_level", "INFO")

    sqlcipher_bin = find_sqlcipher_binary()

    # Watcher debounce settings
    debounce_val = (
        os.environ.get("WECHAT_DEBOUNCE_INTERVAL_MS")
        or os.environ.get("WECHAT_WATCHER_DEBOUNCE_MS")
        or json_cfg.get("debounce_interval_ms")
        or json_cfg.get("watcher_debounce_ms", 500)
    )
    debounce_interval_ms = int(debounce_val)

    max_watches_val = (
        os.environ.get("WECHAT_MAX_WATCHES")
        or os.environ.get("WECHAT_WATCHER_MAX_WATCHES")
        or json_cfg.get("max_watches")
        or json_cfg.get("watcher_max_watches", 50)
    )
    max_watches = int(max_watches_val)

    # Anti-recall watcher settings
    recall_interval_val = (
        os.environ.get("WECHAT_RECALL_INTERVAL_SECONDS")
        or os.environ.get("WECHAT_RECALL_INTERVAL")
        or json_cfg.get("recall_interval_seconds")
        or json_cfg.get("recall_scan_interval_seconds", 3)
    )
    recall_interval_seconds = int(recall_interval_val)

    env_recall_archive = (
        os.environ.get("WECHAT_RECALL_ARCHIVE_PATH")
        or json_cfg.get("recall_archive_path")
    )
    recall_archive_path = Path(env_recall_archive).expanduser().resolve() if env_recall_archive else None

    # Summary pipeline settings
    summary_base_url = (
        os.environ.get("WECHAT_SUMMARY_BASE_URL")
        or json_cfg.get("summary_base_url", "https://api.openai.com/v1")
    )

    summary_api_key = (
        os.environ.get("WECHAT_SUMMARY_API_KEY")
        or json_cfg.get("summary_api_key")
        or None
    )

    summary_model = (
        os.environ.get("WECHAT_SUMMARY_MODEL")
        or json_cfg.get("summary_model", "gpt-4o-mini")
    )

    summary_default_tone = (
        os.environ.get("WECHAT_SUMMARY_DEFAULT_TONE")
        or json_cfg.get("summary_default_tone", "analytical")
    )

    summary_default_template = (
        os.environ.get("WECHAT_SUMMARY_DEFAULT_TEMPLATE")
        or json_cfg.get("summary_default_template", "quick_brief")
    )

    summary_timeout_val = (
        os.environ.get("WECHAT_SUMMARY_TIMEOUT_SECONDS")
        or os.environ.get("WECHAT_SUMMARY_TIMEOUT")
        or json_cfg.get("summary_timeout_seconds", 30)
    )
    summary_timeout_seconds = int(summary_timeout_val)

    return Config(
        db_dir=resolved_db_dir,
        wechat_base_dir=resolved_base_dir,
        keys_file=resolved_keys,
        decrypted_dir=resolved_dec,
        decoded_image_dir=resolved_img,
        runtime_dir=resolved_runtime,
        wxid=resolved_wxid,
        api_host=api_host,
        api_port=api_port,
        sync_interval_seconds=sync_interval,
        log_level=log_level,
        sqlcipher_bin=sqlcipher_bin,
        config_file=target_config if target_config.is_file() else None,
        debounce_interval_ms=debounce_interval_ms,
        max_watches=max_watches,
        recall_interval_seconds=recall_interval_seconds,
        recall_archive_path=recall_archive_path,
        summary_base_url=summary_base_url,
        summary_api_key=summary_api_key,
        summary_model=summary_model,
        summary_default_tone=summary_default_tone,
        summary_default_template=summary_default_template,
        summary_timeout_seconds=summary_timeout_seconds,
    )
