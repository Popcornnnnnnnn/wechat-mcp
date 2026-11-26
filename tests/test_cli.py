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

"""Comprehensive unit tests for the unified Click CLI router and all subcommands."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
import pytest

from tests.fixtures.crypto_generator import generate_synthetic_encrypted_db
from wechat_mcp import __version__
from wechat_mcp.cli import main
from wechat_mcp.config import AccountInfo, Config


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def test_cli_help_lists_all_subcommands(cli_runner: CliRunner):
    """wechat-mcp --help displays description and all 8 expected subcommands."""
    result = cli_runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Unified macOS WeChat MCP server" in result.output

    expected_commands = [
        "api",
        "decrypt",
        "info",
        "keys",
        "mcp",
        "recall",
        "serve",
        "sync",
    ]
    for cmd in expected_commands:
        assert cmd in result.output, f"Missing subcommand in help: {cmd}"


def test_cli_version_flag(cli_runner: CliRunner):
    """wechat-mcp --version outputs the package version."""
    result = cli_runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_invalid_command_exit_code(cli_runner: CliRunner):
    """Non-existent subcommand exits with code 2 and helpful error."""
    result = cli_runner.invoke(main, ["non_existent_command"])
    assert result.exit_code != 0
    assert "No such command" in result.output


def test_cli_unknown_option_exit_code(cli_runner: CliRunner):
    """Unknown global option exits with non-zero exit code."""
    result = cli_runner.invoke(main, ["--unknown-flag"])
    assert result.exit_code != 0
    assert "No such option" in result.output


def test_cli_verbose_flag(cli_runner: CliRunner):
    """Passing -v or --verbose sets loggers to DEBUG level."""
    with patch("logging.getLogger") as mock_get_logger:
        mock_root = MagicMock()
        mock_get_logger.return_value = mock_root
        result = cli_runner.invoke(main, ["-v", "info"])
        assert mock_root.setLevel.called


def test_cli_info_command_with_accounts(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp info renders resolved configuration and accounts."""
    db_storage = tmp_path / "wxid_dummy" / "db_storage"
    db_storage.mkdir(parents=True)
    cfg = Config(
        db_dir=db_storage,
        wechat_base_dir=tmp_path / "wxid_dummy",
        keys_file=tmp_path / "keys.json",
        decrypted_dir=tmp_path / "decrypted",
        decoded_image_dir=tmp_path / "images",
        runtime_dir=tmp_path / "runtime",
        wxid="wxid_dummy",
        api_host="127.0.0.1",
        api_port=8300,
    )
    acc = AccountInfo(
        wxid="wxid_dummy",
        account_dir=tmp_path / "wxid_dummy",
        db_storage_dir=db_storage,
        last_active_time=123456.0,
        is_active=True,
    )

    with patch("wechat_mcp.cli.load_config", return_value=cfg):
        with patch("wechat_mcp.cli.discover_accounts", return_value=[acc]):
            result = cli_runner.invoke(main, ["info"])
            assert result.exit_code == 0
            assert "wechat-mcp Configuration & Discovery" in result.output
            assert "wxid_dummy" in result.output
            assert "[1]* wxid_dummy" in result.output


def test_cli_info_command_no_accounts(cli_runner: CliRunner):
    """wechat-mcp info cleanly informs when no accounts are found."""
    with patch("wechat_mcp.cli.load_config", side_effect=Exception("No accounts found")):
        with patch("wechat_mcp.cli.discover_accounts", return_value=[]):
            result = cli_runner.invoke(main, ["info"])
            assert result.exit_code == 0
            assert "No WeChat accounts discovered." in result.output


def test_cli_decrypt_command_success(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp decrypt successfully decrypts an encrypted SQLite database."""
    key = b"0123456789abcdef0123456789abcdef"
    enc_db = tmp_path / "enc.db"
    out_db = tmp_path / "out.db"
    generate_synthetic_encrypted_db(key, sql_script="CREATE TABLE t(x INT); INSERT INTO t VALUES(42);", output_path=enc_db)

    result = cli_runner.invoke(main, ["decrypt", str(enc_db), str(out_db), "--key", key.hex()])
    assert result.exit_code == 0
    assert "Decryption successful!" in result.output
    assert out_db.is_file()


def test_cli_decrypt_command_invalid_key_fails(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp decrypt with incorrect key fails with exit code 1."""
    key = b"0123456789abcdef0123456789abcdef"
    wrong_key = b"badbadbadbadbadbadbadbadbadbadba"
    enc_db = tmp_path / "enc.db"
    out_db = tmp_path / "out.db"
    generate_synthetic_encrypted_db(key, sql_script="CREATE TABLE t(x INT);", output_path=enc_db)

    result = cli_runner.invoke(main, ["decrypt", str(enc_db), str(out_db), "--key", wrong_key.hex()])
    assert result.exit_code == 1
    assert "Decryption failed" in result.output


def test_cli_decrypt_command_missing_key_flag(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp decrypt without --key flag fails with error."""
    enc_db = tmp_path / "enc.db"
    enc_db.touch()
    out_db = tmp_path / "out.db"

    result = cli_runner.invoke(main, ["decrypt", str(enc_db), str(out_db)])
    assert result.exit_code != 0
    assert "Missing option" in result.output


def test_cli_sync_command_success(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp sync executes SyncManager and outputs summary table."""
    mock_summary = MagicMock()
    mock_summary.total = 10
    mock_summary.synced = 8
    mock_summary.up_to_date = 2
    mock_summary.skipped = 0
    mock_summary.failed = 0
    mock_summary.results = []

    with patch("wechat_mcp.cli.load_config") as mock_load:
        mock_cfg = MagicMock()
        mock_cfg.wxid = "wxid_sync_user"
        mock_load.return_value = mock_cfg

        with patch("wechat_mcp.cli.SyncManager") as mock_sync_mgr:
            instance = mock_sync_mgr.return_value
            instance.sync_all.return_value = mock_summary

            result = cli_runner.invoke(main, ["sync", "--force"])
            assert result.exit_code == 0
            assert "Starting database sync for wxid_sync_user" in result.output
            assert "Synced:     8" in result.output


def test_cli_sync_command_config_failure(cli_runner: CliRunner):
    """wechat-mcp sync exits with status 1 on configuration failure."""
    with patch("wechat_mcp.cli.load_config", side_effect=RuntimeError("Cannot locate storage")):
        result = cli_runner.invoke(main, ["sync"])
        assert result.exit_code == 1
        assert "Error loading configuration" in result.output


def test_cli_mcp_stdio_dispatch(cli_runner: CliRunner):
    """wechat-mcp mcp --transport stdio invokes server.run(transport='stdio')."""
    with patch("wechat_mcp.mcp.create_mcp_server") as mock_create_mcp:
        mock_server = MagicMock()
        mock_create_mcp.return_value = mock_server

        result = cli_runner.invoke(main, ["mcp", "--transport", "stdio"])
        assert result.exit_code == 0
        mock_server.run.assert_called_once_with(transport="stdio")


def test_cli_mcp_sse_dispatch(cli_runner: CliRunner):
    """wechat-mcp mcp --transport sse binds custom host and port."""
    with patch("wechat_mcp.mcp.create_mcp_server") as mock_create_mcp:
        mock_server = MagicMock()
        mock_create_mcp.return_value = mock_server

        result = cli_runner.invoke(main, ["mcp", "--transport", "sse", "--host", "0.0.0.0", "--port", "8355"])
        assert result.exit_code == 0
        mock_server.run.assert_called_once_with(transport="sse", host="0.0.0.0", port=8355)


def test_cli_api_dispatch(cli_runner: CliRunner):
    """wechat-mcp api starts uvicorn server with specified host and port."""
    with patch("uvicorn.run") as mock_uvicorn_run:
        with patch("wechat_mcp.api.create_api_app") as mock_create_app:
            mock_create_app.return_value = MagicMock()
            result = cli_runner.invoke(main, ["api", "--host", "127.0.0.1", "--port", "8300"])
            assert result.exit_code == 0
            assert mock_uvicorn_run.called
            args, kwargs = mock_uvicorn_run.call_args
            assert kwargs["host"] == "127.0.0.1"
            assert kwargs["port"] == 8300


def test_cli_recall_once_mode(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp recall --once executes single scan and prints stats."""
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()

    with patch("wechat_mcp.watcher.recall.RecallArchive.scan", return_value=[]):
        with patch("wechat_mcp.watcher.recall.RecallArchive.get_recall_stats", return_value={"total": 0, "tip": 0, "diff": 0}):
            result = cli_runner.invoke(main, ["recall", "--once", "--archive-dir", str(archive_dir), "--db-dir", str(tmp_path)])
            assert result.exit_code == 0
            assert "RecallArchive initialized" in result.output
            assert "Scan complete. Detected 0 recalled messages." in result.output


@pytest.mark.parametrize("existing_directory", [False, True])
def test_cli_recall_without_config(cli_runner, tmp_path, monkeypatch, existing_directory):
    monkeypatch.chdir(tmp_path)
    decrypted_dir = tmp_path / "decrypted"
    if existing_directory:
        decrypted_dir.mkdir()

    with patch("wechat_mcp.cli.load_config", side_effect=ValueError("No local configuration")):
        result = cli_runner.invoke(main, ["recall", "--once"])

    if existing_directory:
        assert result.exit_code == 0
        assert (decrypted_dir / "recall-archive.sqlite").is_file()
    else:
        assert not decrypted_dir.exists()
        assert result.exit_code == 1
        assert "--db-dir" in result.output


def test_cli_recall_init_failure(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp recall exits with code 1 if archive fails to initialize."""
    with patch("wechat_mcp.watcher.recall.RecallArchive", side_effect=Exception("Database locked")):
        result = cli_runner.invoke(main, ["recall", "--once", "--db-dir", str(tmp_path)])
        assert result.exit_code == 1
        assert "Failed to initialize RecallArchive" in result.output


def test_cli_keys_wechat_not_running(cli_runner: CliRunner):
    """wechat-mcp keys exits with code 1 when WeChat process is not found."""
    with patch("wechat_mcp.crypto.lldb_keys.find_wechat_pid", return_value=None):
        result = cli_runner.invoke(main, ["keys"])
        assert result.exit_code == 1
        assert "WeChat process is not running" in result.output


def test_cli_keys_lldb_success(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp keys extracts keys via LLDB and prints masked keys."""
    fake_keys = {
        "message/message_0.db": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "contact/contact.db": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    }
    keys_out = tmp_path / "out_keys.json"

    with patch("wechat_mcp.crypto.lldb_keys.find_wechat_pid", return_value=1234):
        with patch("wechat_mcp.crypto.lldb_keys.run_lldb_extraction", return_value=fake_keys):
            result = cli_runner.invoke(main, ["keys", "--method", "lldb", "--output", str(keys_out), "--db-dir", str(tmp_path)])
            assert result.exit_code == 0
            assert "Successfully extracted 2 keys" in result.output
            assert "message/message_0.db" in result.output
            # Key masking check: ensure full raw key is not dumped in plaintext stdout
            assert "01234567...89abcdef" in result.output


def test_cli_keys_vm_fallback(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp keys falls back to VM scan in auto mode if LLDB fails."""
    fake_keys = {
        "message/message_1.db": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    }
    keys_out = tmp_path / "vm_keys.json"

    with patch("wechat_mcp.crypto.lldb_keys.find_wechat_pid", return_value=5678):
        with patch("wechat_mcp.crypto.lldb_keys.run_lldb_extraction", side_effect=Exception("LLDB attach disallowed")):
            with patch("wechat_mcp.crypto.vm_scan.scan_process_keys", return_value=fake_keys):
                result = cli_runner.invoke(main, ["keys", "--method", "auto", "--output", str(keys_out), "--db-dir", str(tmp_path)])
                assert result.exit_code == 0
                assert "Successfully extracted 1 keys" in result.output
                assert keys_out.is_file()
                content = json.loads(keys_out.read_text(encoding="utf-8"))
                assert "message/message_1.db" in content


def test_cli_keys_no_keys_found(cli_runner: CliRunner, tmp_path: Path):
    """wechat-mcp keys warns when scan finishes with zero matches."""
    with patch("wechat_mcp.crypto.lldb_keys.find_wechat_pid", return_value=9999):
        with patch("wechat_mcp.crypto.lldb_keys.run_lldb_extraction", return_value={}):
            with patch("wechat_mcp.crypto.vm_scan.scan_process_keys", return_value={}):
                result = cli_runner.invoke(main, ["keys", "--db-dir", str(tmp_path)])
                assert result.exit_code == 0
                assert "no matching database keys were found" in result.output


def test_cli_serve_modes(cli_runner: CliRunner):
    """wechat-mcp serve delegates properly to mcp, api, and composite modes."""
    # Test mode=mcp
    with patch("wechat_mcp.cli.mcp") as mock_mcp:
        result = cli_runner.invoke(main, ["serve", "--mode", "mcp"])
        assert result.exit_code == 0

    # Test mode=api
    with patch("wechat_mcp.cli.api") as mock_api:
        result = cli_runner.invoke(main, ["serve", "--mode", "api"])
        assert result.exit_code == 0

    # Test mode=all composite runner
    with patch("wechat_mcp.api.create_api_app", return_value=MagicMock()):
        with patch("wechat_mcp.mcp.create_mcp_server") as mock_create_mcp:
            mock_srv = MagicMock()
            mock_create_mcp.return_value = mock_srv
            with patch("threading.Thread") as mock_thread_cls:
                mock_thread = MagicMock()
                mock_thread_cls.return_value = mock_thread

                result = cli_runner.invoke(main, ["serve", "--mode", "all", "--port", "8300", "--mcp-port", "8301"])
                assert result.exit_code == 0
                assert "Starting unified wechat-mcp services" in result.output
                assert "REST API:    http://127.0.0.1:8300" in result.output
                assert "FastMCP SSE: http://127.0.0.1:8301/sse" in result.output
                assert mock_thread.start.called
                assert mock_srv.run.called
