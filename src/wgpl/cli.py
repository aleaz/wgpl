import typer
from typer import rich_utils as typer_styles
import json
import os
import sqlite3
import sys
import ipaddress
from pathlib import Path
from typing import Any, Mapping

from rich import box
from rich.console import Console
from rich.table import Table

from . import db
from . import core
from .exceptions import WgplException, InterfaceAlreadyExistsError, PeerAlreadyExistsError, WgBinaryNotFoundError

_HINT_MESSAGES = {
    "re_export_clients": "Re-export client configs (peer config / qr) for peers on this interface.",
    "re_export_client": "Re-export this peer's client config or QR.",
    "apply_server": "Run wgpl apply or interface export to sync the server.",
}

app = typer.Typer(help="WGPL - WireGuard Peer Manager (Lite)")
interface_app = typer.Typer(help="Manage WireGuard interfaces")
peer_app = typer.Typer(help="Manage WireGuard peers")

app.add_typer(interface_app, name="interface")
app.add_typer(peer_app, name="peer")

console = Console(stderr=True) # Always write logs to stderr
out_console = Console() # For stdout tables if not JSON

_STYLE_ID = typer_styles.STYLE_COMMANDS_TABLE_FIRST_COLUMN
_STYLE_VALUE = typer_styles.STYLE_TYPES
_STYLE_META = typer_styles.STYLE_HELPTEXT
_STYLE_BORDER = typer_styles.STYLE_COMMANDS_PANEL_BORDER

_BASE_PUBLIC_PEER_FIELDS = ("id", "interface", "name", "ip_address", "public_key", "created_at")

def _styled(text: str, style: str = "") -> str:
    """Wrap text in Rich markup for a given style (empty = no markup)."""
    if not style:
        return text
    return f"[{style}]{text}[/{style}]"

def _resolve_effective_dns(
    peer_dns: str | None,
    iface_dns: str | None,
) -> str | None:
    if peer_dns:
        return str(peer_dns)
    if iface_dns:
        return str(iface_dns)
    return None

def _public_peer_rows(
    peers: list[sqlite3.Row],
    iface_dns: dict[str, str | None] | None = None,
) -> list[dict[str, str | None]]:
    """Return peer rows safe for JSON output (no private keys or PSK)."""
    iface_dns_map = iface_dns or {}
    rows: list[dict[str, str | None]] = []
    for peer in peers:
        peer_dns = peer["dns"]
        row = {field: peer[field] for field in _BASE_PUBLIC_PEER_FIELDS}
        row["dns"] = _resolve_effective_dns(peer_dns, iface_dns_map.get(peer["interface"]))
        row["dns_override"] = peer_dns
        rows.append(row)
    return rows

def _display_dns(value: str | None) -> str:
    return value if value else "—"

def _interface_dns_map() -> dict[str, str | None]:
    return {row["name"]: row["dns"] for row in db.list_interfaces()}

def _format_peer_id_display(peer_id: str, total_peers: int) -> str:
    """Docker-like ID: full UUID when alone, short prefix when multiple peers."""
    if total_peers == 1:
        return peer_id
    return peer_id.replace("-", "")[:12]

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

    table = Table(
        box=box.ROUNDED,
        expand=True,
        header_style=_STYLE_ID,
        border_style=_STYLE_BORDER,
        show_edge=True,
        pad_edge=True,
    )
    for header, kwargs in columns:
        table.add_column(header, **kwargs)
    for row in rows:
        table.add_row(*row)
    out_console.print()
    out_console.print(f"[bold]{title}[/bold]", justify="center")
    out_console.print()
    out_console.print(table)
    out_console.print()

@app.callback()
def main(
    ctx: typer.Context,
    output_json: bool = typer.Option(False, "--json", "-j", help="Output results in JSON format"),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Disable interactive prompts"),
    db_path: str | None = typer.Option(None, "--db", help="Path to SQLite database")
):
    ctx.ensure_object(dict)
    ctx.obj["json"] = output_json
    ctx.obj["non_interactive"] = non_interactive
    if db_path:
        import os
        os.environ["WGPL_DB_PATH"] = db_path
        
    db.init_db()

def _output(ctx: typer.Context, data: dict | list):
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

def _validate_allowed_ips(allowed_ips: str) -> None:
    for ip in allowed_ips.split(","):
        try:
            ipaddress.ip_network(ip.strip(), strict=False)
        except ValueError:
            console.print(f"[red]WGPL Error: Invalid AllowedIPs format '{ip.strip()}'[/red]")
            sys.exit(1)

# --- Interfaces ---

@interface_app.command("add")
def interface_add(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    endpoint: str = typer.Argument(..., help="Public endpoint (e.g. vpn.example.com)"),
    public_key: str = typer.Argument(..., help="Server public key"),
    address_pool: str = typer.Argument(..., help="Address pool (e.g. 10.0.0.0/24)"),
    port: int = typer.Option(51820, help="Listen port"),
    dns: str | None = typer.Option(None, "--dns", help="Default DNS for client configs (e.g. 1.1.1.1)"),
):
    try:
        # Validate Port
        if not (1 <= port <= 65535):
            console.print(f"[red]WGPL Error: Port must be between 1 and 65535, got {port}.[/red]")
            sys.exit(1)
            
        # Validate Address Pool CIDR
        try:
            ipaddress.IPv4Network(address_pool, strict=False)
        except ValueError as e:
            console.print(f"[red]WGPL Error: Invalid address pool '{address_pool}'. {e}[/red]")
            sys.exit(1)

        normalized_dns = core.validate_dns(dns) if dns is not None else None
        db.add_interface(name, endpoint, public_key, address_pool, port, dns=normalized_dns)
        data = {
            "name": name,
            "endpoint": endpoint,
            "port": port,
            "public_key": public_key,
            "address_pool": address_pool,
        }
        if normalized_dns is not None:
            data["dns"] = normalized_dns
        if ctx.obj.get("json"):
            _output(ctx, data)
        else:
            console.print(f"[green]Added interface {name}[/green]")
    except InterfaceAlreadyExistsError:
        console.print(f"[red]WGPL Error: Interface {name} already exists.[/red]")
        sys.exit(1)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@interface_app.command("remove")
def interface_remove(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name (e.g. wg0)")
):
    try:
        db.remove_interface(name)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "interface": name})
        else:
            console.print(f"[green]Removed interface {name} and all its associated peers.[/green]")
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@interface_app.command("list")
def interface_list(ctx: typer.Context):
    try:
        ifaces = db.list_interfaces()
        data = [dict(row) for row in ifaces]
        if ctx.obj.get("json"):
            _output(ctx, data)
        else:
            rows = [
                [
                    _styled(i["name"], _STYLE_ID),
                    _styled(f"{i['endpoint']}:{i['port']}", ""),
                    _styled(i["address_pool"], _STYLE_META),
                    _styled(_display_dns(i.get("dns")), _STYLE_META),
                ]
                for i in data
            ]
            _print_list_table(
                "WireGuard Interfaces",
                "interfaces",
                [
                    ("Name", {"overflow": "fold"}),
                    ("Endpoint", {"overflow": "fold"}),
                    ("Pool", {"overflow": "fold"}),
                    ("DNS", {"overflow": "fold"}),
                ],
                rows,
            )
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@interface_app.command("export")
def interface_export(ctx: typer.Context, name: str = typer.Argument(..., help="Interface name to export (e.g. wg0)")):
    try:
        conf = core.get_interface_config(name)
        if ctx.obj.get("json"):
            _output(ctx, {"config": conf})
        else:
            print(conf)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@interface_app.command("update")
def interface_update(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    endpoint: str | None = typer.Option(None, "--endpoint", help="Public endpoint hostname"),
    port: int | None = typer.Option(None, "--port", help="Listen port"),
    public_key: str | None = typer.Option(None, "--public-key", help="Server public key"),
    address_pool: str | None = typer.Option(None, "--address-pool", help="Address pool CIDR"),
    dns: str | None = typer.Option(None, "--dns", help="Default DNS for client configs"),
    clear_dns: bool = typer.Option(False, "--clear-dns", help="Remove interface default DNS"),
):
    try:
        if clear_dns and dns is not None:
            console.print("[red]WGPL Error: Cannot use --dns and --clear-dns together.[/red]")
            sys.exit(1)

        result = core.update_interface(
            name,
            endpoint=endpoint,
            port=port,
            public_key=public_key,
            address_pool=address_pool,
            dns=dns,
            clear_dns=clear_dns,
        )
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Updated interface {name}[/green]")
            _print_hints(_extract_hints(result))
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

# --- Peers ---

@peer_app.command("add")
def peer_add(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    name: str = typer.Argument(..., help="Peer name/description"),
    ip: str | None = typer.Option(None, "--ip", help="Peer IP from the interface pool (auto if omitted)"),
    dns: str | None = typer.Option(None, "--dns", help="DNS override for this peer's client config"),
):
    try:
        result = core.add_peer(interface, name, ip_address=ip, dns=dns)
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            dns_note = f", DNS {result['dns']}" if result.get("dns") else ""
            console.print(f"[green]Added peer {name} ({result['ip_address']}{dns_note})[/green]")
    except PeerAlreadyExistsError as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("remove")
def peer_remove(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)")
):
    try:
        canonical_id = core.resolve_peer_ref(peer_id, interface)
        core.remove_peer(interface, peer_id)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "id": canonical_id, "input": peer_id})
        else:
            console.print(f"[green]Removed peer {peer_id}[/green]")
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("update")
def peer_update(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    name: str | None = typer.Option(None, "--name", help="New peer name"),
    ip: str | None = typer.Option(None, "--ip", help="New peer IP from the interface pool"),
    dns: str | None = typer.Option(None, "--dns", help="DNS override for this peer's client config"),
    clear_dns: bool = typer.Option(False, "--clear-dns", help="Remove peer DNS override (inherit interface default)"),
):
    try:
        if clear_dns and dns is not None:
            console.print("[red]WGPL Error: Cannot use --dns and --clear-dns together.[/red]")
            sys.exit(1)

        result = core.update_peer(
            interface,
            peer_id,
            name=name,
            ip_address=ip,
            dns=dns,
            clear_dns=clear_dns,
        )
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Updated peer {peer_id}[/green]")
            _print_hints(_extract_hints(result))
    except PeerAlreadyExistsError as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("list")
def peer_list(ctx: typer.Context, interface: str | None = typer.Option(None, help="Filter by interface")):
    try:
        peers = db.list_peers(interface)
        iface_dns = _interface_dns_map()
        if ctx.obj.get("json"):
            _output(ctx, _public_peer_rows(peers, iface_dns))
        else:
            data = [dict(p) for p in peers]
            total_peers = len(data)
            rows = [
                [
                    _styled(_format_peer_id_display(p["id"], total_peers), _STYLE_ID),
                    _styled(p["interface"], ""),
                    _styled(p["name"], _STYLE_ID),
                    _styled(p["ip_address"], _STYLE_VALUE),
                    _styled(
                        _display_dns(_resolve_effective_dns(p["dns"], iface_dns.get(p["interface"]))),
                        _STYLE_META,
                    ),
                    _styled(p["created_at"], _STYLE_META),
                ]
                for p in data
            ]
            _print_list_table(
                "WireGuard Peers",
                "peers",
                [
                    ("ID", {"overflow": "fold"}),
                    ("Interface", {"overflow": "fold"}),
                    ("Name", {"overflow": "fold"}),
                    ("IP Address", {}),
                    ("DNS", {"overflow": "fold"}),
                    ("Created At", {"overflow": "fold"}),
                ],
                rows,
            )
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("config")
def peer_config(
    ctx: typer.Context, 
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    allowed_ips: str = typer.Option("0.0.0.0/0", help="AllowedIPs for the client"),
    keepalive: int = typer.Option(25, help="PersistentKeepalive interval")
):
    try:
        _validate_allowed_ips(allowed_ips)
        config = core.get_peer_config(peer_id, allowed_ips=allowed_ips, keepalive=keepalive)
        if ctx.obj.get("json"):
            _output(ctx, {"config": config})
        else:
            print(config) # print to stdout
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("qr")
def peer_qr(
    ctx: typer.Context,
    peer_id: str = typer.Argument(..., help="Peer ID or unique prefix (e.g. 55c521ad2d94)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write QR code as PNG to this file"),
    allowed_ips: str = typer.Option("0.0.0.0/0", help="AllowedIPs for the client"),
    keepalive: int = typer.Option(25, help="PersistentKeepalive interval"),
):
    try:
        _validate_allowed_ips(allowed_ips)
        if output is not None:
            png_bytes = core.get_peer_qr_png_bytes(
                peer_id, allowed_ips=allowed_ips, keepalive=keepalive
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
            qr = core.get_peer_qr(peer_id, allowed_ips=allowed_ips, keepalive=keepalive)
            if ctx.obj.get("json"):
                _output(ctx, {"qr": qr})
            else:
                print(qr)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

# --- Validate ---

@app.command("validate")
def validate_cmd(
    ctx: typer.Context,
    interface: str | None = typer.Argument(None, help="Interface name to check (all if omitted)"),
):
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
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

# --- Apply ---

@app.command("apply")
def apply(ctx: typer.Context, interface: str = typer.Argument(..., help="Interface name to sync (e.g. wg0)")):
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
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    app()
