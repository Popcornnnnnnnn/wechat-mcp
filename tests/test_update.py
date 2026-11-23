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

"""Offline unit tests for wechat-mcp update notifications and `upgrade`."""
from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from wechat_mcp import __version__, update
from wechat_mcp.cli import main


class _FakeTTYStream(io.StringIO):
    def __init__(self, tty: bool = True) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_semver_comparison() -> None:
    assert update.is_newer_version("0.1.2", "0.1.1") is True
    assert update.is_newer_version("v0.2.0", "0.1.1") is True
    assert update.is_newer_version("0.1.1", "0.1.1.dev1") is True
    assert update.is_newer_version("0.1.1", "0.1.1") is False
    assert update.is_newer_version("v0.1.0", "0.1.1") is False
    assert update.is_newer_version("0.1.1-rc.1", "0.1.1") is False


def test_should_check_updates_suppresses_mcp_serve_and_non_tty() -> None:
    tty_err = _FakeTTYStream(True)
    non_tty_err = _FakeTTYStream(False)

    assert update.should_check_updates("info", env={}, stderr=tty_err) is True
    assert update.should_check_updates(None, env={}, stderr=tty_err) is False
    assert update.should_check_updates("mcp", env={}, stderr=tty_err) is False
    assert update.should_check_updates("serve", env={}, stderr=tty_err) is False
    assert update.should_check_updates("upgrade", env={}, stderr=tty_err) is False
    assert update.should_check_updates("info", env={}, stderr=non_tty_err) is False
    assert update.should_check_updates("info", env={"CI": "true"}, stderr=tty_err) is False
    assert update.should_check_updates("info", env={"WECHAT_MCP_NO_UPDATE_CHECK": "1"}, stderr=tty_err) is False


def test_fresh_and_stale_cache_behavior(tmp_path: Path) -> None:
    cache_file = tmp_path / "update-check.json"
    now = 1_700_000_000.0

    # Missing cache spawns background refresh without printing
    err = _FakeTTYStream(True)
    spawned: list[Path] = []
    notice = update.maybe_notify_update(
        "0.1.1", subcommand="info", cache_path=cache_file, env={}, stderr=err, spawn_refresh=spawned.append, now=now
    )
    assert notice is None
    assert err.getvalue() == ""
    assert spawned == [cache_file]

    # Fresh cache with newer version prints notice and does not spawn
    cache_file.write_text(json.dumps({"checked_at": now - 60, "latest_version": "0.1.2"}), encoding="utf-8")
    err = _FakeTTYStream(True)
    spawned = []
    notice = update.maybe_notify_update(
        "0.1.1", subcommand="info", cache_path=cache_file, env={}, stderr=err, spawn_refresh=spawned.append, now=now
    )
    assert notice is not None and "wechat-mcp v0.1.2" in err.getvalue()
    assert "wechat-mcp upgrade" in err.getvalue()
    assert spawned == []

    # Stale cache spawns refresh and still notifies if cached newer
    cache_file.write_text(
        json.dumps({"checked_at": now - update.CHECK_INTERVAL_SECONDS - 5, "latest_version": "0.2.0"}),
        encoding="utf-8",
    )
    err = _FakeTTYStream(True)
    spawned = []
    update.maybe_notify_update(
        "0.1.1", subcommand="info", cache_path=cache_file, env={}, stderr=err, spawn_refresh=spawned.append, now=now
    )
    assert "wechat-mcp v0.2.0" in err.getvalue()
    assert spawned == [cache_file]


def test_run_upgrade_check_json_and_mocked_installers(tmp_path: Path) -> None:
    cache_file = tmp_path / "update-check.json"
    release = update.ReleaseInfo(
        tag_name="v0.1.2",
        version="0.1.2",
        release_url="https://github.com/Popcornnnnnnnn/wechat-mcp/releases/tag/v0.1.2",
        wheel_url="https://github.com/Popcornnnnnnnn/wechat-mcp/releases/download/v0.1.2/wechat_mcp-0.1.2-py3-none-any.whl",
    )

    out = io.StringIO()
    err = io.StringIO()
    code = update.run_upgrade(
        check_only=True,
        as_json=True,
        current_version="0.1.1",
        cache_path=cache_file,
        fetch_fn=lambda timeout=10.0: release,
        stdout=out,
        stderr=err,
        executable="/opt/homebrew/Cellar/wechat-mcp/0.1.1/libexec/venv/bin/python",
    )
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["current"] == "0.1.1"
    assert payload["latest"] == "0.1.2"
    assert payload["update_available"] is True
    assert payload["install_method"] == "homebrew"
    assert cache_file.is_file()

    # Homebrew upgrade
    ran: list[list[str]] = []
    code = update.run_upgrade(
        current_version="0.1.1",
        cache_path=cache_file,
        fetch_fn=lambda timeout=10.0: release,
        runner=lambda cmd, check=False: ran.append(cmd) or SimpleNamespace(returncode=0),
        stdout=io.StringIO(),
        stderr=err,
        executable="/opt/homebrew/Cellar/wechat-mcp/0.1.1/libexec/venv/bin/python",
    )
    assert code == 0
    assert ran == [["brew", "update"], ["brew", "upgrade", "Popcornnnnnnnn/tap/wechat-mcp"]]

    # uv upgrade
    ran = []
    code = update.run_upgrade(
        current_version="0.1.1",
        cache_path=cache_file,
        fetch_fn=lambda timeout=10.0: release,
        runner=lambda cmd, check=False: ran.append(cmd) or SimpleNamespace(returncode=0),
        stdout=io.StringIO(),
        stderr=err,
        executable="/Users/test/.local/share/uv/tools/wechat-mcp/bin/python",
        module_file="/Users/test/.local/share/uv/tools/wechat-mcp/lib/python3.12/site-packages/wechat_mcp/update.py",
    )
    assert code == 0
    assert ran == [["uv", "tool", "install", "--force", release.wheel_url]]


def test_cli_upgrade_help_and_version() -> None:
    runner = CliRunner()
    res_help = runner.invoke(main, ["upgrade", "--help"])
    assert res_help.exit_code == 0
    assert "--check" in res_help.output
    assert "--json" in res_help.output

    res_ver = runner.invoke(main, ["--version"])
    assert res_ver.exit_code == 0
    assert __version__ in res_ver.output
