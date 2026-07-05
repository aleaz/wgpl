import typer
from typer import rich_utils as typer_styles
import json
import os
import sqlite3
import sys
import shutil
import tempfile
import ipaddress
from pathlib import Path
from typing import Any, Mapping

from rich import box
from rich.console import Console
from rich.table import Table

from . import core
from . import db
from .exceptions import (
    AmbiguousInterfaceError,
    InterfaceAlreadyExistsError,
    InterfaceNotFoundError,
    PeerAlreadyExistsError,
    PeerNotFoundError,
    WgBinaryNotFoundError,
    WgplException,
)

_HINT_MESSAGES = {
    "re_export_clients": "Re-export client configs (peer config / qr) for peers on this interface.",
    "re_export_client": "Re-export this peer's client config or QR.",
    "apply_server": "Run wgpl apply or interface export to sync the server.",
}

app = typer.Typer(help="WGPL - WireGuard Peer Manager (Lite)")
interface_app = typer.Typer(help="Manage WireGuard interfaces")
peer_app = typer.Typer(help="Manage WireGuard peers")
db_app = typer.Typer(help="Manage the SQLite database (Backup & Restore)")

app.add_typer(interface_app, name="interface")
app.add_typer(peer_app, name="peer")
app.add_typer(db_app, name="db")

console = Console(stderr=True) # Always write logs to stderr
out_console = Console() # For stdout tables if not JSON

_STYLE_ID = typer_styles.STYLE_COMMANDS_TABLE_FIRST_COLUMN
_STYLE_VALUE = typer_styles.STYLE_TYPES
_STYLE_META = typer_styles.STYLE_HELPTEXT
_STYLE_BORDER = typer_styles.STYLE_COMMANDS_PANEL_BORDER

_BASE_PUBLIC_PEER_FIELDS = ("id", "interface_id", "name", "ip_address", "public_key", "created_at")

def _styled(text: str, style: str = "") -> str:
    """Wrap text in Rich markup for a given style (empty = no markup)."""
    if not style:
        return text
    return f"[{style}]{text}[/{style}]"

def _public_peer_rows(
    peers: list[sqlite3.Row],
    iface_dns: dict[int, str | None] | None = None,
) -> list[dict[str, str | None]]:
    """Return peer rows safe for JSON output (no private keys or PSK)."""
    iface_dns_map = iface_dns or {}
    rows: list[dict[str, str | None]] = []
    for peer in peers:
        peer_dns = peer["dns"]
        row = {field: str(peer[field]) if peer[field] is not None else None for field in _BASE_PUBLIC_PEER_FIELDS}
        row["dns"] = core.get_effective_dns(peer_dns, iface_dns_map.get(peer["interface_id"]))
        row["interface_id"] = str(peer["interface_id"])
        row["dns_override"] = peer_dns
        row["status"] = core.get_peer_status(peer)
        row["expires_at"] = peer["expires_at"] if "expires_at" in peer.keys() else None
        row["deleted_at"] = peer["deleted_at"] if "deleted_at" in peer.keys() else None
        rows.append(row)
    return rows

def _display_dns(value: str | None) -> str:
    return value if value else "—"

def _truncate_desc(desc: str | None, max_len: int = 25) -> str:
    if not desc:
        return "—"
    if len(desc) > max_len:
        return desc[: max_len - 3] + "..."
    return desc

def _format_peer_id_display(peer_id: str, total_peers: int) -> str:
    """Docker-like ID: full UUID when alone, short prefix when multiple peers."""
    if total_peers == 1:
        return peer_id
    return peer_id.replace("-", "")[:12]

def _create_base_table(
    expand: bool = True,
    show_header: bool = True,
    header_style: str | None = None,
) -> Table:
    """Create a Table instance with the standard CLI design tokens."""
    return Table(
        box=box.ROUNDED,
        expand=expand,
        border_style=_STYLE_BORDER,
        show_edge=True,
        pad_edge=True,
        show_header=show_header,
        header_style=header_style,
    )

def _print_titled_table(title: str, table: Table) -> None:
    """Print a Rich table centered and formatted with standard spacing."""
    out_console.print()
    out_console.print(f"[bold]{title}[/bold]", justify="center")
    out_console.print()
    out_console.print(table)
    out_console.print()

def _print_show_table(
    title: str,
    rows: list[tuple[str, str]],
) -> None:
    """Print a vertical Rich table for detailed inspection aligned with Typer help styling."""
    table = _create_base_table(show_header=False)
    table.add_column("Field", style=_STYLE_ID)
    table.add_column("Value")
    for k, v in rows:
        table.add_row(k, v)
    _print_titled_table(title, table)

def _print_list_table(
    title: str,
    empty_label: str,
    columns: list[tuple[str, dict[str, Any]]],
    rows: list[list[str]],
) -> None:
    """Print a full-width Rich table aligned with Typer help styling."""
    if not rows:
        console.print(f"[{typer_styles.STYLE_USAGE}]No {empty_label} found.[/{typer_styles.STYLE_USAGE}]")
        return

    table = _create_base_table(header_style=_STYLE_ID)
    for header, kwargs in columns:
        table.add_column(header, **kwargs)
    for row in rows:
        table.add_row(*row)
    _print_titled_table(title, table)

@app.callback()
def main(
    ctx: typer.Context,
    output_json: bool = typer.Option(False, "--json", "-j", help="Output results in JSON format"),
    db_path: str | None = typer.Option(None, "--db", help="Path to SQLite database")
) -> None:
    """Initialize the CLI application context and database connection."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = output_json
    if db_path:
        os.environ["WGPL_DB_PATH"] = db_path

    # Inject execution context for auditing
    os.environ["WGPL_EXEC_CMD"] = " ".join(sys.argv)

    try:
        core.ensure_database()
    except WgplException as e:
        _exit_error(ctx, str(e))

def _exit_error(ctx: typer.Context | None, message: str, code: int = 1) -> None:
    """Print a user-facing error and exit (JSON on stdout when --json is set)."""
    console.print(f"[red]WGPL Error: {message}[/red]")
    if ctx is not None and ctx.obj.get("json"):
        print(json.dumps({"status": "error", "message": message}))
    sys.exit(code)

def _output(ctx: typer.Context, data: dict[str, Any] | list[Any]) -> None:
    """Output data as JSON to stdout if the --json flag was provided."""
    if ctx.obj.get("json"):
        print(json.dumps(data))

def _extract_hints(result: Mapping[str, object]) -> list[str]:
    hints = result.get("hints")
    if isinstance(hints, list):
        return [hint for hint in hints if isinstance(hint, str)]
    return []

def _print_hints(hints: list[str]) -> None:
    for hint in hints:
        message = _HINT_MESSAGES.get(hint, hint)
        console.print(f"[yellow]Hint: {message}[/yellow]")

def _validate_allowed_ips(ctx: typer.Context, allowed_ips: str) -> None:
    for ip in allowed_ips.split(","):
        try:
            ipaddress.ip_network(ip.strip(), strict=False)
        except ValueError:
            _exit_error(ctx, f"Invalid AllowedIPs format '{ip.strip()}'")

# --- Interfaces ---

@interface_app.command("add")
def interface_add(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    endpoint: str = typer.Argument(..., help="Public endpoint (e.g. vpn.example.com)"),
    public_key: str = typer.Argument(..., help="Server public key"),
    address_pool: str = typer.Argument(..., help="Address pool (e.g. 10.0.0.0/24)"),
    port: int = typer.Option(51820, help="Listen port"),
    dns: str | None = typer.Option(None, "--dns", help="Default DNS for client configs (e.g. 1.1.1.1)"),
    desc: str | None = typer.Option(None, "--desc", help="Description of the interface"),
    mtu: int | None = typer.Option(None, "--mtu", help="Global MTU for the interface and clients"),
    keepalive: int | None = typer.Option(None, "--keepalive", help="Global PersistentKeepalive for clients"),
) -> None:
    try:
        result = core.add_interface(
            name, endpoint, public_key, address_pool, port=port, dns=dns, desc=desc, mtu=mtu, keepalive=keepalive
        )
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Added interface {name}[/green]")
    except InterfaceAlreadyExistsError:
        _exit_error(ctx, f"Interface {name} already exists.")
    except (WgplException, ValueError) as e:
        _exit_error(ctx, str(e))

@interface_app.command("remove")
def interface_remove(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Delete the interface and all peers (required when peers remain)",
    ),
) -> None:
    try:
        core.remove_interface(interface, force=force)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "interface": interface, "force": force})
        else:
            if force:
                console.print(f"[green]Removed interface {interface} and all its associated peers.[/green]")
            else:
                console.print(f"[green]Removed interface {interface}.[/green]")
    except AmbiguousInterfaceError as e:
        _exit_error(ctx, str(e))
    except WgplException as e:
        _exit_error(ctx, str(e))

@interface_app.command("list")
def interface_list(ctx: typer.Context) -> None:
    try:
        data = core.list_interfaces()
        if ctx.obj.get("json"):
            _output(ctx, data)
        else:
            rows = [
                [
                    _styled(str(i["id"]), _STYLE_ID),
                    _styled(i["name"], _STYLE_ID),
                    _styled(f"{i['endpoint']}:{i['port']}", ""),
                    _styled(i["address_pool"], _STYLE_META),
                    _styled(_display_dns(i.get("dns")), _STYLE_META),
                    _styled(str(i.get("mtu") or "—"), _STYLE_META),
                    _styled(str(i.get("keepalive") or "—"), _STYLE_META),
                    _styled(_truncate_desc(i.get("desc")), ""),
                ]
                for i in data
            ]
            _print_list_table(
                "WireGuard Interfaces",
                "interfaces",
                [
                    ("ID", {"style": _STYLE_ID, "no_wrap": True}),
                    ("Name", {"style": _STYLE_ID, "no_wrap": True}),
                    ("Endpoint:Port", {"no_wrap": True}),
                    ("Address Pool", {}),
                    ("DNS", {}),
                    ("MTU", {}),
                    ("Keepalive", {}),
                    ("Description", {}),
                ],
                rows,
            )
    except WgplException as e:
        _exit_error(ctx, str(e))

@interface_app.command("export")
def interface_export(ctx: typer.Context, interface: str = typer.Argument(..., help="Interface name or ID to export (e.g. wg0 or 1)")) -> None:
    try:
        conf = core.get_interface_config(interface)
        if ctx.obj.get("json"):
            _output(ctx, {"config": conf})
        else:
            print(conf)
    except AmbiguousInterfaceError as e:
        _exit_error(ctx, str(e))
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("show")
def peer_show(
    ctx: typer.Context,
    interface: str | None = typer.Option(None, help="Interface name or ID (e.g. wg0 or 1)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix"),
) -> None:
    try:
        # Fetching peer data
        peers = core.list_peers(interface, expired_only=False, show_all=True)
        # Resolve ID correctly
        resolved_id = core.resolve_peer_ref(peer_id, interface, active_only=False)
        peer = next((p for p in peers if p["id"] == resolved_id), None)
        if not peer:
            raise PeerNotFoundError(f"Peer {peer_id} not found")

        iface_dns = core.interface_dns_map()

        if ctx.obj.get("json"):
            _output(ctx, dict(peer))
        else:
            rows = [
                ("ID", str(peer["id"])),
                ("Name", str(peer["name"])),
                ("Interface", str(peer["interface"])),
                ("Status", str(core.get_peer_status(dict(peer)))),
                ("IP Address", str(peer["ip_address"])),
                ("Public Key", str(peer["public_key"])),
                ("Preshared Key", str(dict(peer).get("preshared_key") or "—")),
                ("DNS (Effective)", str(core.get_effective_dns(dict(peer).get("dns"), iface_dns.get(peer["interface"])) or "—")),
                ("DNS (Override)", str(dict(peer).get("dns") or "—")),
                ("MTU", str(dict(peer).get("mtu") or "—")),
                ("Keepalive", str(dict(peer).get("keepalive") or "—")),
                ("Expires At", str(dict(peer).get("expires_at") or "—")),
                ("Deleted At", str(dict(peer).get("deleted_at") or "—")),
                ("Description", str(dict(peer).get("desc") or "—")),
            ]
            _print_show_table(f"Peer Details: {peer['name']}", rows)
    except WgplException as e:
        _exit_error(ctx, str(e))

@interface_app.command("show")
def interface_show(ctx: typer.Context, name: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)")) -> None:
    try:
        iface_id = core.resolve_interface_ref(name)
        interface = db.get_interface(iface_id)
        if not interface:
            raise InterfaceNotFoundError(f"Interface {name} not found")

        if ctx.obj.get("json"):
            _output(ctx, dict(interface))
        else:
            rows = [
                ("Name", str(interface["name"])),
                ("Endpoint", str(interface["endpoint"])),
                ("Port", str(interface["port"])),
                ("Public Key", str(interface["public_key"])),
                ("Address Pool", str(interface["address_pool"])),
                ("DNS", str(dict(interface).get("dns") or "—")),
                ("MTU", str(dict(interface).get("mtu") or "—")),
                ("Keepalive", str(dict(interface).get("keepalive") or "—")),
                ("Description", str(dict(interface).get("desc") or "—")),
            ]
            _print_show_table(f"Interface Details: {name}", rows)
    except WgplException as e:
        _exit_error(ctx, str(e))

@interface_app.command("update")
def interface_update(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    endpoint: str | None = typer.Option(None, "--endpoint", help="Public endpoint hostname"),
    port: int | None = typer.Option(None, "--port", help="Listen port"),
    public_key: str | None = typer.Option(None, "--public-key", help="Server public key"),
    address_pool: str | None = typer.Option(None, "--address-pool", help="Address pool CIDR"),
    dns: str | None = typer.Option(None, "--dns", help="Default DNS for client configs"),
    clear_dns: bool = typer.Option(False, "--clear-dns", help="Remove interface default DNS"),
    desc: str | None = typer.Option(None, "--desc", help="Description of the interface"),
    clear_desc: bool = typer.Option(False, "--clear-desc", help="Remove interface description"),
    mtu: int | None = typer.Option(None, "--mtu", help="Global MTU for the interface and clients"),
    clear_mtu: bool = typer.Option(False, "--clear-mtu", help="Remove interface MTU"),
    keepalive: int | None = typer.Option(None, "--keepalive", help="Global PersistentKeepalive for clients"),
    clear_keepalive: bool = typer.Option(False, "--clear-keepalive", help="Remove interface PersistentKeepalive"),
) -> None:
    try:
        if clear_dns and dns is not None:
            _exit_error(ctx, "Cannot use --dns and --clear-dns together.")
        if clear_desc and desc is not None:
            _exit_error(ctx, "Cannot use --desc and --clear-desc together.")
        if clear_mtu and mtu is not None:
            _exit_error(ctx, "Cannot use --mtu and --clear-mtu together.")
        if clear_keepalive and keepalive is not None:
            _exit_error(ctx, "Cannot use --keepalive and --clear-keepalive together.")

        result = core.update_interface(
            name,
            endpoint=endpoint,
            port=port,
            public_key=public_key,
            address_pool=address_pool,
            dns=dns,
            clear_dns=clear_dns,
            desc=desc,
            clear_desc=clear_desc,
            mtu=mtu,
            clear_mtu=clear_mtu,
            keepalive=keepalive,
            clear_keepalive=clear_keepalive,
        )
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Updated interface {name}[/green]")
            _print_hints(_extract_hints(result))
    except (WgplException, ValueError) as e:
        _exit_error(ctx, str(e))

# --- Peers ---

@peer_app.command("add")
def peer_add(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    name: str = typer.Argument(..., help="Peer name/description"),
    ip: str | None = typer.Option(None, "--ip", help="Peer IP from the interface pool (auto if omitted)"),
    dns: str | None = typer.Option(None, "--dns", help="DNS override for this peer's client config"),
    expires: str | None = typer.Option(None, "--expires", help="Duration until expiration (e.g. 7d, 24h)"),
    desc: str | None = typer.Option(None, "--desc", help="Description of the peer"),
    mtu: int | None = typer.Option(None, "--mtu", help="MTU override for this peer"),
    keepalive: int | None = typer.Option(None, "--keepalive", help="PersistentKeepalive override for this peer"),
) -> None:
    try:
        result = core.add_peer(interface, name, ip_address=ip, dns=dns, expires=expires, desc=desc, mtu=mtu, keepalive=keepalive)
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            dns_note = f", DNS {result['dns']}" if result.get("dns") else ""
            console.print(f"[green]Added peer {name} ({result['ip_address']}{dns_note})[/green]")
    except PeerAlreadyExistsError as e:
        _exit_error(ctx, str(e))
    except (WgplException, ValueError) as e:
        _exit_error(ctx, str(e))

@interface_app.command("history")
def interface_history(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    limit: int = typer.Option(100, "--limit", help="Maximum audit events to return"),
) -> None:
    try:
        events = core.list_interface_audit_history(name, limit=limit)
        if ctx.obj.get("json"):
            _output(ctx, events)
        else:
            if not events:
                console.print(f"[yellow]No audit history for interface {name}.[/yellow]")
                return
            rows = [
                [
                    _styled(str(e["occurred_at"]), _STYLE_META),
                    _styled(str(e.get("actor", "unknown")), _STYLE_VALUE),
                    _styled(str(e["event_type"]), _STYLE_ID),
                    _styled(str(e.get("metadata") or ""), ""),
                ]
                for e in reversed(events)
            ]
            _print_list_table(
                f"Audit history: {name}",
                "events",
                [
                    ("When", {"overflow": "fold"}),
                    ("Actor", {"overflow": "fold"}),
                    ("Event", {"overflow": "fold"}),
                    ("Metadata", {"overflow": "fold"}),
                ],
                rows,
            )
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("history")
def peer_history(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix"),
    limit: int = typer.Option(100, "--limit", help="Maximum audit events to return"),
) -> None:
    try:
        events = core.list_peer_audit_history(peer_id, interface, limit=limit)
        if ctx.obj.get("json"):
            _output(ctx, events)
        else:
            if not events:
                console.print(f"[yellow]No audit history for peer {peer_id}.[/yellow]")
                return
            rows = [
                [
                    _styled(str(e["occurred_at"]), _STYLE_META),
                    _styled(str(e.get("actor", "unknown")), _STYLE_VALUE),
                    _styled(str(e["event_type"]), _STYLE_ID),
                    _styled(str(e.get("name") or ""), _STYLE_VALUE),
                    _styled(str(e.get("ip_address") or ""), _STYLE_META),
                ]
                for e in reversed(events)
            ]
            _print_list_table(
                f"Audit history: {peer_id}",
                "events",
                [
                    ("When", {"overflow": "fold"}),
                    ("Actor", {"overflow": "fold"}),
                    ("Event", {"overflow": "fold"}),
                    ("Name", {"overflow": "fold"}),
                    ("IP", {"overflow": "fold"}),
                ],
                rows,
            )
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("remove")
def peer_remove(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    hard: bool = typer.Option(False, "--hard", help="Physically delete the peer instead of soft-deleting"),
) -> None:
    try:
        canonical_id = core.resolve_peer_ref(peer_id, interface, active_only=False)
        core.remove_peer(interface, canonical_id, hard=hard)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "id": canonical_id, "input": peer_id})
        else:
            console.print(f"[green]Removed peer {peer_id}[/green]")
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("prune")
def peer_prune(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
) -> None:
    try:
        deleted = core.prune_peers(interface)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "interface": interface, "deleted_count": deleted})
        else:
            console.print(f"[green]Pruned {deleted} expired or soft-deleted peers from {interface}[/green]")
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("update")
def peer_update(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name or ID (e.g. wg0 or 1)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    name: str | None = typer.Option(None, "--name", help="New peer name"),
    ip: str | None = typer.Option(None, "--ip", help="New peer IP from the interface pool"),
    dns: str | None = typer.Option(None, "--dns", help="DNS override for this peer's client config"),
    clear_dns: bool = typer.Option(False, "--clear-dns", help="Remove peer DNS override (inherit interface default)"),
    desc: str | None = typer.Option(None, "--desc", help="Description of the peer"),
    clear_desc: bool = typer.Option(False, "--clear-desc", help="Remove peer description"),
    mtu: int | None = typer.Option(None, "--mtu", help="MTU override for this peer"),
    clear_mtu: bool = typer.Option(False, "--clear-mtu", help="Remove peer MTU override (inherit interface default)"),
    keepalive: int | None = typer.Option(None, "--keepalive", help="PersistentKeepalive override for this peer"),
    clear_keepalive: bool = typer.Option(False, "--clear-keepalive", help="Remove peer PersistentKeepalive override (inherit interface default)"),
    expires: str | None = typer.Option(None, "--expires", help="When the peer should expire (e.g., '30d', '1y')"),
    clear_expires: bool = typer.Option(False, "--clear-expires", help="Remove peer expiration"),
) -> None:
    try:
        if clear_dns and dns is not None:
            _exit_error(ctx, "Cannot use --dns and --clear-dns together.")
        if clear_desc and desc is not None:
            _exit_error(ctx, "Cannot use --desc and --clear-desc together.")
        if clear_mtu and mtu is not None:
            _exit_error(ctx, "Cannot use --mtu and --clear-mtu together.")
        if clear_keepalive and keepalive is not None:
            _exit_error(ctx, "Cannot use --keepalive and --clear-keepalive together.")
        if clear_expires and expires is not None:
            _exit_error(ctx, "Cannot use --expires and --clear-expires together.")

        result = core.update_peer(
            interface,
            peer_id,
            active_only=False,
            name=name,
            ip_address=ip,
            dns=dns,
            clear_dns=clear_dns,
            desc=desc,
            clear_desc=clear_desc,
            mtu=mtu,
            clear_mtu=clear_mtu,
            keepalive=keepalive,
            clear_keepalive=clear_keepalive,
            expires=expires,
            clear_expires=clear_expires,
        )
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Updated peer {peer_id}[/green]")
            _print_hints(_extract_hints(result))
    except PeerAlreadyExistsError as e:
        _exit_error(ctx, str(e))
    except (WgplException, ValueError) as e:
        _exit_error(ctx, str(e))

@peer_app.command("list")
def peer_list(
    ctx: typer.Context, 
    interface: str | None = typer.Option(None, help="Filter by interface"),
    expired: bool = typer.Option(False, "--expired", help="Show only expired peers"),
    all: bool = typer.Option(False, "--all", help="Show all peers including deleted ones"),
) -> None:
    try:
        peers = core.list_peers(interface, expired_only=expired, show_all=all)

        iface_dns: dict[int, str | None] = core.interface_dns_map()
        iface_map = {iface["id"]: iface["name"] for iface in core.list_interfaces()}
        if ctx.obj.get("json"):
            _output(ctx, _public_peer_rows(peers, iface_dns))
        else:
            data = [dict(p) for p in peers]
            total_peers = len(data)
            rows = [
                [
                    _styled(_format_peer_id_display(p["id"], total_peers), _STYLE_ID),
                    _styled(str(iface_map.get(p["interface_id"], p["interface_id"])), ""),
                    _styled(p["name"], _STYLE_ID),
                    _styled(p["ip_address"], _STYLE_VALUE),
                    _styled(core.get_peer_status(p), _STYLE_META),
                    _styled(
                        _display_dns(core.get_effective_dns(p["dns"], iface_dns.get(p["interface_id"]))),
                        _STYLE_META,
                    ),
                    _styled(str(p.get("mtu") or "—"), _STYLE_META),
                    _styled(str(p.get("keepalive") or "—"), _STYLE_META),
                    _styled(_truncate_desc(p.get("desc")), ""),
                ]
                for p in data
            ]
            _print_list_table(
                "WireGuard Peers",
                "peers",
                [
                    ("ID", {"overflow": "fold"}),
                    ("Interface", {}),
                    ("Name", {"overflow": "fold"}),
                    ("IP", {"overflow": "fold"}),
                    ("Status", {}),
                    ("DNS", {"overflow": "fold"}),
                    ("MTU", {"overflow": "fold"}),
                    ("Keepalive", {"overflow": "fold"}),
                    ("Desc", {"overflow": "fold"}),
                ],
                rows,
            )
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("config")
def peer_config(
    ctx: typer.Context, 
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    allowed_ips: str = typer.Option("0.0.0.0/0", help="AllowedIPs for the client"),
) -> None:
    try:
        _validate_allowed_ips(ctx, allowed_ips)
        config = core.get_peer_config(peer_id, allowed_ips=allowed_ips)
        if ctx.obj.get("json"):
            _output(ctx, {"config": config})
        else:
            print(config) # print to stdout
    except WgplException as e:
        _exit_error(ctx, str(e))

@peer_app.command("qr")
def peer_qr(
    ctx: typer.Context,
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write QR code as PNG to this file"),
    allowed_ips: str = typer.Option("0.0.0.0/0", help="AllowedIPs for the client"),
) -> None:
    try:
        _validate_allowed_ips(ctx, allowed_ips)
        if output is not None:
            png_bytes = core.get_peer_qr_png_bytes(
                peer_id, allowed_ips=allowed_ips
            )
            output.write_bytes(png_bytes)
            os.chmod(output, 0o600)
            canonical_id = core.resolve_peer_ref(peer_id)
            if ctx.obj.get("json"):
                _output(ctx, {"status": "success", "path": str(output), "peer_id": canonical_id})
            else:
                console.print(
                    f"[green]Wrote QR code to {output}[/green] "
                    "[yellow](contains private keys; keep file permissions restricted)[/yellow]"
                )
        else:
            qr = core.get_peer_qr(peer_id, allowed_ips=allowed_ips)
            if ctx.obj.get("json"):
                _output(ctx, {"qr": qr})
            else:
                print(qr)
    except WgplException as e:
        _exit_error(ctx, str(e))

# --- Validate ---

@app.command("validate")
def validate_cmd(
    ctx: typer.Context,
    interface: str | None = typer.Argument(None, help="Interface name to check (all if omitted)"),
) -> None:
    """Validate database consistency (peer IPs in pool, DNS values)."""
    try:
        result = core.validate_state(interface)
        if ctx.obj.get("json"):
            _output(ctx, result)
        elif result["status"] == "ok":
            scope = interface or "database"
            console.print(f"[green]Validation passed for {scope}[/green]")
        else:
            issues = result["issues"]
            assert isinstance(issues, list)
            for issue in issues:
                peer_part = f" peer {issue['peer']}" if issue.get("peer") else ""
                console.print(
                    f"[red]{issue['interface']}{peer_part}: "
                    f"{issue['code']} — {issue['detail']}[/red]"
                )
        if result["status"] != "ok":
            sys.exit(1)
    except WgplException as e:
        _exit_error(ctx, str(e))

# --- Database ---

@db_app.command("dump")
def db_dump(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", "-o", help="File to write binary backup to")
) -> None:
    """Export the database as a binary SQLite backup."""
    try:
        console.print(
            "[yellow]Warning: Output is a binary SQLite database file.[/yellow]"
        )
        if output:
            core.dump_database(str(output))
            os.chmod(output, 0o600)
        else:
            fd, path = tempfile.mkstemp()
            try:
                os.close(fd)
                core.dump_database(path)
                with open(path, "rb") as f:
                    shutil.copyfileobj(f, sys.stdout.buffer)
            finally:
                os.remove(path)
    except WgplException as e:
        _exit_error(ctx, str(e))

@db_app.command("restore")
def db_restore(
    ctx: typer.Context,
    file: str = typer.Argument(
        "-", 
        help="Binary SQLite file to restore from (use '-' for stdin)"
    )
) -> None:
    """Restore the database from a binary SQLite backup (destructive)."""
    try:
        if file == "-":
            fd, path = tempfile.mkstemp()
            try:
                with os.fdopen(fd, 'wb') as f:
                    shutil.copyfileobj(sys.stdin.buffer, f)
                warnings = core.restore_database(path)
            finally:
                os.remove(path)
        else:
            warnings = core.restore_database(file)
            
        for warning in warnings:
            console.print(f"[yellow]{warning}[/yellow]")
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "action": "restore", "warnings": warnings})
        else:
            console.print("[green]Database successfully restored.[/green]")
    except WgplException as e:
        _exit_error(ctx, str(e))

# --- Apply ---

@app.command("apply")
def apply(ctx: typer.Context, interface: str = typer.Argument(..., help="Interface name to sync (e.g. wg0)")) -> None:
    """Syncs the WireGuard interface with the database state."""
    try:
        core.sync_interface(interface)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "action": "apply", "interface": interface})
        else:
            console.print(f"[green]Successfully applied DB state to {interface}[/green]")
    except WgBinaryNotFoundError as e:
        console.print(f"[yellow]Notice: {e}[/yellow]")
        console.print("[blue]If you are running WGPL remotely, use `wgpl interface export <name>` instead to extract the config and pipe it via SSH.[/blue]")
        sys.exit(1)
    except WgplException as e:
        _exit_error(ctx, str(e))

if __name__ == "__main__":
    app()
