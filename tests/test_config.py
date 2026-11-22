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

"""Comprehensive unit tests for configuration discovery, loading, and precedence."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from wechat_mcp.config import (
    AccountInfo,
    Config,
    WeChatConfig,
    WeChatConfigError,
    discover_accounts,
    discover_wechat_accounts,
    discover_wechat_db_dir,
    find_sqlcipher_binary,
    get_active_db_storage,
    get_user_home,
    load_config,
)


def test_config_dataclass_defaults(tmp_path: Path):
    """Test Config dataclass default values and field types."""
    db_dir = tmp_path / "db_storage"
    base_dir = tmp_path
    keys_file = tmp_path / "keys.json"
    decrypted_dir = tmp_path / "decrypted"
    image_dir = tmp_path / "images"
    runtime_dir = tmp_path / "runtime"

    cfg = Config(
        db_dir=db_dir,
        wechat_base_dir=base_dir,
        keys_file=keys_file,
        decrypted_dir=decrypted_dir,
        decoded_image_dir=image_dir,
        runtime_dir=runtime_dir,
        wxid="wxid_test123",
    )

    assert cfg.api_host == "127.0.0.1"
    assert cfg.api_port == 8300
    assert cfg.sync_interval_seconds == 20
    assert cfg.log_level == "INFO"
    assert cfg.sqlcipher_bin is None
    assert cfg.config_file is None
    assert cfg.debounce_interval_ms == 500
    assert cfg.max_watches == 50
    assert cfg.recall_interval_seconds == 3
    assert cfg.recall_archive_path is None
    assert cfg.summary_base_url == "https://api.openai.com/v1"
    assert cfg.summary_api_key is None
    assert cfg.summary_model == "gpt-4o-mini"
    assert cfg.summary_default_tone == "analytical"
    assert cfg.summary_default_template == "quick_brief"
    assert cfg.summary_timeout_seconds == 30
    assert WeChatConfig is Config


def test_config_to_dict_serialization(tmp_path: Path):
    """Test to_dict produces a complete JSON-serializable dictionary with all fields."""
    db_dir = tmp_path / "db_storage"
    archive_path = tmp_path / "archive.sqlite"
    cfg = Config(
        db_dir=db_dir,
        wechat_base_dir=tmp_path,
        keys_file=tmp_path / "keys.json",
        decrypted_dir=tmp_path / "decrypted",
        decoded_image_dir=tmp_path / "images",
        runtime_dir=tmp_path / "runtime",
        wxid="wxid_serial",
        recall_archive_path=archive_path,
        summary_api_key="sk-test-key",
    )

    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert d["wxid"] == "wxid_serial"
    assert d["db_dir"] == str(db_dir)
    assert d["recall_archive_path"] == str(archive_path)
    assert d["summary_api_key"] == "sk-test-key"
    assert d["debounce_interval_ms"] == 500
    assert d["max_watches"] == 50
    assert d["recall_interval_seconds"] == 3
    assert d["summary_model"] == "gpt-4o-mini"

    # Must be valid JSON string
    serialized = json.dumps(d)
    deserialized = json.loads(serialized)
    assert deserialized["wxid"] == "wxid_serial"


def test_config_precedence_explicit_argument_over_env_and_file(tmp_path: Path, monkeypatch):
    """Explicit load_config arguments take precedence over environment variables and JSON config."""
    file_db = tmp_path / "file_db"
    file_db.mkdir()
    env_db = tmp_path / "env_db"
    env_db.mkdir()
    arg_db = tmp_path / "arg_db"
    arg_db.mkdir()

    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({"db_dir": str(file_db), "api_port": 9000}), encoding="utf-8")

    monkeypatch.setenv("WECHAT_DB_DIR", str(env_db))
    monkeypatch.setenv("WECHAT_API_PORT", "9001")

    # Pass explicit arg_db
    cfg = load_config(config_file=cfg_file, db_dir=arg_db)
    assert cfg.db_dir == arg_db.resolve()
    # Env var takes precedence over file for api_port
    assert cfg.api_port == 9001


def test_config_env_vars_full_parsing(tmp_path: Path, monkeypatch):
    """Verify parsing of all environment variables."""
    db_storage = tmp_path / "my_account" / "db_storage"
    db_storage.mkdir(parents=True)
    archive = tmp_path / "my_archive.sqlite"

    monkeypatch.setenv("WECHAT_DB_DIR", str(db_storage))
    monkeypatch.setenv("WECHAT_API_HOST", "0.0.0.0")
    monkeypatch.setenv("WECHAT_API_PORT", "8400")
    monkeypatch.setenv("WECHAT_SYNC_INTERVAL", "45")
    monkeypatch.setenv("WECHAT_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("WECHAT_DEBOUNCE_INTERVAL_MS", "250")
    monkeypatch.setenv("WECHAT_MAX_WATCHES", "100")
    monkeypatch.setenv("WECHAT_RECALL_INTERVAL_SECONDS", "5")
    monkeypatch.setenv("WECHAT_RECALL_ARCHIVE_PATH", str(archive))
    monkeypatch.setenv("WECHAT_SUMMARY_BASE_URL", "https://custom.ai.api/v1")
    monkeypatch.setenv("WECHAT_SUMMARY_API_KEY", "env-secret-token")
    monkeypatch.setenv("WECHAT_SUMMARY_MODEL", "gpt-4o")
    monkeypatch.setenv("WECHAT_SUMMARY_DEFAULT_TONE", "executive")
    monkeypatch.setenv("WECHAT_SUMMARY_DEFAULT_TEMPLATE", "deep_dive")
    monkeypatch.setenv("WECHAT_SUMMARY_TIMEOUT_SECONDS", "60")

    cfg = load_config()
    assert cfg.db_dir == db_storage.resolve()
    assert cfg.wxid == "my_account"
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8400
    assert cfg.sync_interval_seconds == 45
    assert cfg.log_level == "DEBUG"
    assert cfg.debounce_interval_ms == 250
    assert cfg.max_watches == 100
    assert cfg.recall_interval_seconds == 5
    assert cfg.recall_archive_path == archive.resolve()
    assert cfg.summary_base_url == "https://custom.ai.api/v1"
    assert cfg.summary_api_key == "env-secret-token"
    assert cfg.summary_model == "gpt-4o"
    assert cfg.summary_default_tone == "executive"
    assert cfg.summary_default_template == "deep_dive"
    assert cfg.summary_timeout_seconds == 60


def test_config_json_file_loading(tmp_path: Path):
    """Verify loading complete configuration from a JSON file."""
    db_storage = tmp_path / "wxid_from_file" / "db_storage"
    db_storage.mkdir(parents=True)
    archive_file = tmp_path / "recall.sqlite"

    cfg_data = {
        "db_dir": str(db_storage),
        "api_host": "127.0.0.2",
        "api_port": 8500,
        "sync_interval_seconds": 15,
        "log_level": "WARNING",
        "debounce_interval_ms": 750,
        "max_watches": 80,
        "recall_interval_seconds": 4,
        "recall_archive_path": str(archive_file),
        "summary_base_url": "https://api.openai.com/v1",
        "summary_api_key": "file-secret-key",
        "summary_model": "gpt-4o-mini",
        "summary_default_tone": "conversational",
        "summary_default_template": "bullet_points",
        "summary_timeout_seconds": 40,
    }
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    cfg = Config.load(config_file=cfg_file)
    assert cfg.db_dir == db_storage.resolve()
    assert cfg.wxid == "wxid_from_file"
    assert cfg.api_host == "127.0.0.2"
    assert cfg.api_port == 8500
    assert cfg.sync_interval_seconds == 15
    assert cfg.log_level == "WARNING"
    assert cfg.debounce_interval_ms == 750
    assert cfg.max_watches == 80
    assert cfg.recall_interval_seconds == 4
    assert cfg.recall_archive_path == archive_file.resolve()
    assert cfg.summary_api_key == "file-secret-key"
    assert cfg.summary_default_tone == "conversational"
    assert cfg.summary_default_template == "bullet_points"
    assert cfg.summary_timeout_seconds == 40
    assert cfg.config_file == cfg_file.resolve()


def test_config_missing_file_fallback(tmp_path: Path):
    """Non-existent config_file falls back cleanly without exception."""
    db_dir = tmp_path / "my_db"
    db_dir.mkdir()
    non_existent = tmp_path / "missing.json"

    cfg = load_config(config_file=non_existent, db_dir=db_dir)
    assert cfg.db_dir == db_dir.resolve()
    assert cfg.config_file is None
    assert cfg.api_port == 8300


def test_config_malformed_json_fallback(tmp_path: Path):
    """Malformed config_file falls back cleanly without crash."""
    db_dir = tmp_path / "my_db"
    db_dir.mkdir()
    broken_json = tmp_path / "broken.json"
    broken_json.write_text("{this is not valid json!@#$", encoding="utf-8")

    cfg = load_config(config_file=broken_json, db_dir=db_dir)
    assert cfg.db_dir == db_dir.resolve()
    assert cfg.api_port == 8300


def test_discover_accounts_sorted_by_activity(tmp_path: Path, monkeypatch):
    """Discovered accounts are sorted descending by last_active_time with is_active flag."""
    search_root = tmp_path / "xwechat_files"
    search_root.mkdir()

    # User 1: older activity
    u1 = search_root / "wxid_user_old"
    u1_db = u1 / "db_storage"
    u1_db.mkdir(parents=True)
    os.utime(u1_db, (1000.0, 1000.0))

    # User 2: newer activity
    u2 = search_root / "wxid_user_new"
    u2_db = u2 / "db_storage"
    u2_msg = u2_db / "message"
    u2_msg.mkdir(parents=True)
    os.utime(u2_msg, (5000.0, 5000.0))

    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [search_root])

    accounts = discover_accounts()
    assert len(accounts) == 2
    assert accounts[0].wxid == "wxid_user_new"
    assert accounts[0].is_active is True
    assert accounts[1].wxid == "wxid_user_old"
    assert accounts[1].is_active is False

    paths = discover_wechat_accounts()
    assert paths[0] == u2.resolve()
    assert paths[1] == u1.resolve()

    active_storage = get_active_db_storage()
    assert active_storage == u2_db.resolve()

    discovered_db = discover_wechat_db_dir()
    assert discovered_db == u2_db.resolve()


def test_discover_accounts_ignores_system_dirs(tmp_path: Path, monkeypatch):
    """System directories such as all_users, Backup, temp, crash are ignored."""
    search_root = tmp_path / "xwechat_files"
    search_root.mkdir()

    for sys_name in ["all_users", "Backup", "temp", "crash", ".DS_Store"]:
        d = search_root / sys_name / "db_storage"
        d.mkdir(parents=True)

    # Valid user
    valid = search_root / "wxid_legit" / "db_storage"
    valid.mkdir(parents=True)

    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [search_root])

    accounts = discover_accounts()
    assert len(accounts) == 1
    assert accounts[0].wxid == "wxid_legit"


def test_load_config_specific_wxid_matching(tmp_path: Path, monkeypatch):
    """Specifying wxid resolves that specific account even if not most active."""
    search_root = tmp_path / "xwechat_files"
    search_root.mkdir()

    u1 = search_root / "wxid_primary" / "db_storage"
    u1.mkdir(parents=True)
    os.utime(u1, (5000.0, 5000.0))

    u2 = search_root / "wxid_secondary" / "db_storage"
    u2.mkdir(parents=True)
    os.utime(u2, (1000.0, 1000.0))

    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [search_root])

    cfg = load_config(wxid="wxid_secondary")
    assert cfg.wxid == "wxid_secondary"
    assert cfg.db_dir == u2.resolve()


def test_load_config_nonexistent_wxid_raises_error(tmp_path: Path, monkeypatch):
    """Requesting an account wxid that doesn't exist raises WeChatConfigError."""
    search_root = tmp_path / "xwechat_files"
    search_root.mkdir()
    (search_root / "wxid_only" / "db_storage").mkdir(parents=True)

    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [search_root])

    with pytest.raises(WeChatConfigError, match="Specified WeChat account wxid 'wxid_missing' not found"):
        load_config(wxid="wxid_missing")


def test_load_config_no_accounts_raises_error(tmp_path: Path, monkeypatch):
    """When no accounts exist and no db_dir is passed, raises WeChatConfigError."""
    empty_root = tmp_path / "empty_roots"
    empty_root.mkdir()

    monkeypatch.setattr("wechat_mcp.config.get_search_roots", lambda: [empty_root])
    monkeypatch.delenv("WECHAT_DB_DIR", raising=False)

    with pytest.raises(WeChatConfigError, match="No WeChat accounts found"):
        load_config()


def test_find_sqlcipher_binary_env_override(tmp_path: Path, monkeypatch):
    """find_sqlcipher_binary respects SQLCIPHER_PATH environment variable."""
    fake_bin = tmp_path / "fake_sqlcipher"
    fake_bin.touch(mode=0o755)

    monkeypatch.setenv("SQLCIPHER_PATH", str(fake_bin))
    found = find_sqlcipher_binary()
    assert found == fake_bin.resolve()


def test_find_sqlcipher_binary_fallback_none(monkeypatch):
    """find_sqlcipher_binary returns None when binary is not found anywhere."""
    monkeypatch.delenv("SQLCIPHER_PATH", raising=False)
    monkeypatch.delenv("WECHAT_SQLCIPHER_PATH", raising=False)
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    with patch("pathlib.Path.is_file", return_value=False):
        found = find_sqlcipher_binary()
        assert found is None


def test_get_user_home_sudo_user(monkeypatch, tmp_path: Path):
    """get_user_home respects SUDO_USER when directory exists."""
    sudo_home = tmp_path / "sudo_user_home"
    sudo_home.mkdir()

    monkeypatch.setenv("SUDO_USER", "test_sudo_user")
    with patch("sys.platform", "darwin"):
        with patch("pathlib.Path.is_dir", lambda p: str(p) == f"/Users/test_sudo_user"):
            assert get_user_home() == Path("/Users/test_sudo_user")


def test_config_example_json_completeness():
    """Verify config.example.json contains all required fields without sensitive values."""
    config_path = Path(__file__).resolve().parent.parent / "config.example.json"
    assert config_path.is_file()

    data = json.loads(config_path.read_text(encoding="utf-8"))
    required_keys = [
        "wxid",
        "db_dir",
        "decrypted_dir",
        "keys_file",
        "decoded_image_dir",
        "runtime_dir",
        "sqlcipher_bin",
        "api_host",
        "api_port",
        "mcp_transport",
        "mcp_port",
        "sync_interval_seconds",
        "log_level",
        "debounce_interval_ms",
        "max_watches",
        "recall_interval_seconds",
        "recall_archive_path",
        "summary_base_url",
        "summary_api_key",
        "summary_model",
        "summary_default_tone",
        "summary_default_template",
        "summary_timeout_seconds",
    ]
    for key in required_keys:
        assert key in data, f"Missing key in config.example.json: {key}"

    # Sanitization check: no real passwords or tokens
    assert data["summary_api_key"] is None or data["summary_api_key"] == ""
    assert data["wxid"] == ""
    assert not any("/Users/" in str(v) for v in data.values() if isinstance(v, str))
