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

"""Command-line interface entrypoints for wechat-mcp."""
from __future__ import annotations

import json
import logging
from pathlib import Path
import sys
import threading
from typing import Optional

import click

from wechat_mcp import __version__
from wechat_mcp.config import discover_accounts, load_config
from wechat_mcp.crypto.decrypt import decrypt_database
from wechat_mcp.crypto.sync import SyncManager
from wechat_mcp.update import maybe_notify_update, run_upgrade

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("wechat_mcp.cli")


def _notify_update_safe(subcommand: str | None) -> None:
    try:
        maybe_notify_update(__version__, subcommand=subcommand)
    except Exception:
        pass


@click.group()
@click.version_option(version=__version__, prog_name="wechat-mcp")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging output")
@click.pass_context
def main(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """Unified macOS WeChat MCP server, database decryptor, and history service."""
    ctx.ensure_object(dict)
    ctx.obj["config_file"] = config
    ctx.obj["verbose"] = verbose
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    ctx.call_on_close(lambda: _notify_update_safe(ctx.invoked_subcommand))


def _resolve_config_path(ctx: click.Context, local_config: str | None) -> str | None:
    """Resolve config file path from local subcommand option or global context."""
    if local_config:
        return local_config
    if ctx and ctx.obj and ctx.obj.get("config_file"):
        return ctx.obj.get("config_file")
    return None


@main.command()
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage directory")
@click.option("--wxid", default=None, help="Target WeChat account wxid")
@click.pass_context
def info(ctx: click.Context, config: str | None, db_dir: str | None, wxid: str | None) -> None:
    """Display discovered WeChat configuration, accounts, and storage paths."""
    config_file = _resolve_config_path(ctx, config)
    click.echo("=" * 60)
    click.echo("wechat-mcp Configuration & Discovery")
    click.echo("=" * 60)

    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir, wxid=wxid)
        click.echo(f"Active WXID:       {cfg.wxid}")
        click.echo(f"DB Storage Dir:    {cfg.db_dir}")
        click.echo(f"Decrypted Dir:     {cfg.decrypted_dir}")
        click.echo(f"Keys File:         {cfg.keys_file} (exists: {cfg.keys_file.is_file()})")
        click.echo(f"SQLCipher Binary:  {cfg.sqlcipher_bin or 'None (using pure-Python)'}")
        click.echo(f"API Endpoint:      http://{cfg.api_host}:{cfg.api_port}")
    except Exception as e:
        click.echo(f"Configuration resolution failed: {e}", err=True)

    click.echo("\nDiscovered Accounts:")
    try:
        accounts = discover_accounts()
        if not accounts:
            click.echo("  No WeChat accounts discovered.")
        for idx, acc in enumerate(accounts, 1):
            star = "*" if acc.is_active else " "
            click.echo(f"  [{idx}]{star} {acc.wxid} -> {acc.db_storage_dir}")
    except Exception as e:
        click.echo(f"  Error discovering accounts: {e}")


@main.command()
@click.option("--method", "-m", type=click.Choice(["auto", "lldb", "vm"]), default="auto", help="Key extraction method")
@click.option("--output", "-o", type=click.Path(), default=None, help="Path to output keys.json")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage directory to verify keys against")
@click.option("--pid", type=int, default=None, help="WeChat process PID (auto-discovered if omitted)")
@click.option("--timeout", type=int, default=180, help="Timeout in seconds for LLDB extraction")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def keys(ctx: click.Context, method: str, output: str | None, db_dir: str | None, pid: int | None, timeout: int, config: str | None) -> None:
    """Extract SQLite encryption keys from running WeChat process via LLDB or VM scan."""
    from wechat_mcp.crypto.lldb_keys import find_wechat_pid, run_lldb_extraction
    from wechat_mcp.crypto.vm_scan import scan_process_keys

    config_file = _resolve_config_path(ctx, config)
    cfg = None
    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir)
    except Exception as e:
        logger.debug("Config load note: %s", e)

    target_db_dir = Path(db_dir).expanduser().resolve() if db_dir else (cfg.db_dir if cfg else None)
    target_output = Path(output).expanduser().resolve() if output else (cfg.keys_file if cfg else Path("keys.json"))
    target_pid = pid or find_wechat_pid()

    if not target_pid:
        click.secho("Error: WeChat process is not running. Please start WeChat first.", fg="red", err=True)
        sys.exit(1)

    click.echo(f"Extracting WeChat encryption keys (method={method}, pid={target_pid})...")
    discovered_keys: dict[str, str] = {}

    try:
        if method in ("lldb", "auto"):
            try:
                discovered_keys = run_lldb_extraction(
                    db_dir=target_db_dir or Path("."),
                    output_keys_file=target_output,
                    pid=target_pid,
                    timeout_seconds=timeout,
                )
            except Exception as e:
                if method == "auto":
                    logger.info("LLDB extraction failed (%s); falling back to Mach VM scan", e)
                else:
                    raise

        if not discovered_keys and method in ("vm", "auto"):
            discovered_keys = scan_process_keys(pid=target_pid, db_dir=target_db_dir)
            if discovered_keys:
                target_output.parent.mkdir(parents=True, exist_ok=True)
                formatted = {rel: {"enc_key": k} for rel, k in discovered_keys.items()}
                with open(target_output, "w", encoding="utf-8") as f:
                    json.dump(formatted, f, indent=2)

        if discovered_keys:
            click.secho(f"Successfully extracted {len(discovered_keys)} keys -> {target_output}", fg="green")
            for rel, k in discovered_keys.items():
                masked = k[:8] + "..." + k[-8:] if len(k) >= 16 else "***"
                click.echo(f"  {rel:<35} {masked}")
        else:
            click.secho("Key extraction completed but no matching database keys were found.", fg="yellow")
    except Exception as e:
        click.secho(f"Error extracting keys: {e}", fg="red", err=True)
        sys.exit(1)


@main.command()
@click.option("--force", "-f", is_flag=True, help="Force sync even if up to date")
@click.option("--db-dir", type=click.Path(), default=None, help="Source db_storage directory")
@click.option("--keys", "-k", type=click.Path(), default=None, help="Path to keys.json")
@click.option("--output", "-o", type=click.Path(), default=None, help="Decrypted output directory")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def sync(ctx: click.Context, force: bool, db_dir: str | None, keys: str | None, output: str | None, config: str | None) -> None:
    """Synchronize, snapshot, checkpoint WAL, and decrypt WeChat databases."""
    config_file = _resolve_config_path(ctx, config)
    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir, keys_file=keys, decrypted_dir=output)
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)

    manager = SyncManager(cfg)
    click.echo(f"Starting database sync for {cfg.wxid}...")
    summary = manager.sync_all(force=force)

    click.echo("\nSync Summary:")
    click.echo(f"  Total:      {summary.total}")
    click.echo(f"  Synced:     {summary.synced}")
    click.echo(f"  Up-to-date: {summary.up_to_date}")
    click.echo(f"  Skipped:    {summary.skipped}")
    click.echo(f"  Failed:     {summary.failed}")

    for res in summary.results:
        status_color = "green" if res.status.value in ("synced", "up-to-date") else "yellow"
        if res.status.value == "failed":
            status_color = "red"
        click.secho(f"  {res.status.value:<14} {res.rel_path} ({res.duration_ms:.1f}ms)", fg=status_color)
        if res.error:
            click.secho(f"    Error: {res.error}", fg="red")


@main.command()
@click.argument("db_path", type=click.Path(exists=True))
@click.argument("output_path", type=click.Path())
@click.option("--key", "-k", required=True, help="32-byte encryption key (raw or 64-hex)")
def decrypt(db_path: str, output_path: str, key: str) -> None:
    """Decrypt a single SQLCipher database file to SQLite format."""
    click.echo(f"Decrypting {db_path} -> {output_path}...")
    success = decrypt_database(Path(db_path), Path(output_path), key)
    if success:
        click.secho("Decryption successful!", fg="green")
    else:
        click.secho("Decryption failed (check key and file integrity).", fg="red", err=True)
        sys.exit(1)


@main.command()
@click.option("--transport", type=click.Choice(["stdio", "sse"]), default="stdio", help="MCP transport mechanism")
@click.option("--host", default=None, help="Host to bind for SSE transport")
@click.option("--port", type=int, default=None, help="Port to bind for SSE transport")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage directory")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def mcp(ctx: click.Context, transport: str, host: str | None, port: int | None, db_dir: str | None, config: str | None) -> None:
    """Run the FastMCP server exposing 40 tools."""
    from wechat_mcp.mcp import create_mcp_server

    config_file = _resolve_config_path(ctx, config)
    cfg = None
    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir)
    except Exception as e:
        logger.debug("Config load note: %s", e)

    server = create_mcp_server(cfg)
    click.echo(f"Starting FastMCP server with transport={transport}...", err=True)
    if transport == "stdio":
        server.run(transport="stdio")
    else:
        h = host or "127.0.0.1"
        p = port or 8301
        server.run(transport="sse", host=h, port=p)


@main.command()
@click.option("--host", default=None, help="Host address to bind")
@click.option("--port", type=int, default=None, help="Port to bind")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage directory")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def api(ctx: click.Context, host: str | None, port: int | None, db_dir: str | None, config: str | None) -> None:
    """Run the FastAPI REST query service on port 8300."""
    import uvicorn
    from wechat_mcp.api import create_api_app

    config_file = _resolve_config_path(ctx, config)
    cfg = None
    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir)
    except Exception as e:
        logger.debug("Config load note: %s", e)

    bind_host = host or (cfg.api_host if cfg else "127.0.0.1")
    bind_port = port or (cfg.api_port if cfg else 8300)
    app = create_api_app(cfg)
    click.echo(f"Starting WeChat REST API at http://{bind_host}:{bind_port}...")
    uvicorn.run(app, host=bind_host, port=bind_port)


@main.command()
@click.option("--interval", "-i", type=float, default=2.0, help="Polling interval in seconds between scans")
@click.option("--archive-dir", "-a", type=click.Path(), default=None, help="Directory to store recall archive database")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage or decrypted directory")
@click.option("--session", "-s", default=None, help="Specific session/chatroom to watch (default: all)")
@click.option("--once", is_flag=True, help="Run single scan and exit")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def recall(ctx: click.Context, interval: float, archive_dir: str | None, db_dir: str | None, session: str | None, once: bool, config: str | None) -> None:
    """Run anti-recall watcher with dual-signal detection and message archiving."""
    import time
    from wechat_mcp.watcher.recall import RecallArchive

    config_file = _resolve_config_path(ctx, config)
    cfg = None
    try:
        cfg = load_config(config_file=config_file, db_dir=db_dir)
    except Exception as e:
        logger.debug("Config load note: %s", e)

    target_db_dir = Path(db_dir) if db_dir else (cfg.decrypted_dir if cfg else Path("decrypted"))
    archive_path = (Path(archive_dir) / "recall-archive.sqlite") if archive_dir else (
        cfg.recall_archive_path if cfg and cfg.recall_archive_path else None
    )

    try:
        archive = RecallArchive(target_db_dir, archive_path=archive_path)
    except Exception as e:
        click.secho(f"Failed to initialize RecallArchive: {e}", fg="red", err=True)
        sys.exit(1)

    click.echo(f"RecallArchive initialized (archive_path={archive.archive_path})")
    click.echo(f"Monitoring DB directory: {target_db_dir}")

    if once:
        click.echo("Running single scan...")
        detected = archive.scan(session=session)
        click.secho(f"Scan complete. Detected {len(detected)} recalled messages.", fg="green")
        for rec in detected:
            click.echo(f"  [{rec.get('source')}] {rec.get('session')} | {rec.get('sender')}: {rec.get('content')}")
        stats = archive.get_recall_stats()
        click.echo(f"Total archived: {stats.get('total', 0)} (tip: {stats.get('tip', 0)}, diff: {stats.get('diff', 0)})")
        return

    click.echo(f"Starting anti-recall watcher (interval={interval}s, press Ctrl+C to stop)...")
    try:
        while True:
            try:
                detected = archive.scan(session=session)
                if detected:
                    for rec in detected:
                        click.secho(
                            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] RECALL DETECTED ({rec.get('source')}): "
                            f"{rec.get('session')} <{rec.get('sender')}>: {rec.get('content')}",
                            fg="yellow",
                        )
            except Exception as e:
                logger.error("Error during recall scan: %s", e)
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("\nStopping anti-recall watcher.")


@main.command()
@click.option("--host", default=None, help="Host address to bind")
@click.option("--port", type=int, default=None, help="Port to bind for REST API")
@click.option("--mcp-port", type=int, default=None, help="Port to bind for FastMCP SSE server")
@click.option("--mode", type=click.Choice(["all", "mcp", "api"]), default="all", help="Service mode to start")
@click.option("--db-dir", type=click.Path(), default=None, help="WeChat db_storage directory")
@click.option("--config", "-c", type=click.Path(dir_okay=False), default=None, help="Path to config.json file")
@click.pass_context
def serve(ctx: click.Context, host: str | None, port: int | None, mcp_port: int | None, mode: str, db_dir: str | None, config: str | None) -> None:
    """Unified service runner hosting REST API and MCP server."""
    if mode == "mcp":
        ctx.invoke(mcp, transport="stdio", host=host, port=mcp_port, db_dir=db_dir, config=config)
    elif mode == "api":
        ctx.invoke(api, host=host, port=port, db_dir=db_dir, config=config)
    else:
        # mode == "all": run FastAPI on port 8300 and FastMCP on SSE port 8301
        import uvicorn
        from wechat_mcp.api import create_api_app
        from wechat_mcp.mcp import create_mcp_server

        config_file = _resolve_config_path(ctx, config)
        cfg = None
        try:
            cfg = load_config(config_file=config_file, db_dir=db_dir)
        except Exception as e:
            logger.debug("Config load note: %s", e)

        bind_host = host or (cfg.api_host if cfg else "127.0.0.1")
        api_p = port or (cfg.api_port if cfg else 8300)
        sse_p = mcp_port or 8301

        click.echo("=" * 60)
        click.echo("Starting unified wechat-mcp services:")
        click.echo(f"  REST API:    http://{bind_host}:{api_p}")
        click.echo(f"  FastMCP SSE: http://{bind_host}:{sse_p}/sse")
        click.echo("=" * 60)

        api_app = create_api_app(cfg)
        mcp_srv = create_mcp_server(cfg)

        api_thread = threading.Thread(
            target=lambda: uvicorn.run(api_app, host=bind_host, port=api_p, log_level="warning"),
            daemon=True,
        )
        api_thread.start()
        mcp_srv.run(transport="sse", host=bind_host, port=sse_p)


@main.command()
@click.option("--check", is_flag=True, default=False, help="Check for updates without installing")
@click.option("--json", "as_json", is_flag=True, default=False, help="Print update check result as JSON")
def upgrade(check: bool, as_json: bool) -> None:
    """Check for new wechat-mcp releases and upgrade the installed tool."""
    code = run_upgrade(check_only=check, as_json=as_json)
    if code != 0:
        sys.exit(code)


if __name__ == "__main__":
    main()
