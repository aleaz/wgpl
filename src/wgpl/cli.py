import typer
import json
import sqlite3
import sys
import ipaddress
from rich.console import Console
from rich.table import Table

from . import db
from . import core
from .exceptions import WgplException, InterfaceAlreadyExistsError, PeerAlreadyExistsError, WgBinaryNotFoundError

app = typer.Typer(help="WGPL - WireGuard Peer Manager (Lite)")
interface_app = typer.Typer(help="Manage WireGuard interfaces")
peer_app = typer.Typer(help="Manage WireGuard peers")

app.add_typer(interface_app, name="interface")
app.add_typer(peer_app, name="peer")

console = Console(stderr=True) # Always write logs to stderr
out_console = Console() # For stdout tables if not JSON

_PUBLIC_PEER_FIELDS = ("id", "interface", "name", "ip_address", "public_key", "created_at")

def _public_peer_rows(peers: list[sqlite3.Row]) -> list[dict[str, str]]:
    """Return peer rows safe for JSON output (no private keys or PSK)."""
    return [{field: peer[field] for field in _PUBLIC_PEER_FIELDS} for peer in peers]

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
    port: int = typer.Option(51820, help="Listen port")
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

        db.add_interface(name, endpoint, public_key, address_pool, port)
        data = {"name": name, "endpoint": endpoint, "port": port, "public_key": public_key, "address_pool": address_pool}
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
            table = Table(title="WireGuard Interfaces")
            table.add_column("Name")
            table.add_column("Endpoint")
            table.add_column("Pool")
            for i in data:
                table.add_row(i["name"], f"{i['endpoint']}:{i['port']}", i["address_pool"])
            out_console.print(table)
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

# --- Peers ---

@peer_app.command("add")
def peer_add(
    ctx: typer.Context,
    interface: str = typer.Argument(..., help="Interface name (e.g. wg0)"),
    name: str = typer.Argument(..., help="Peer name/description")
):
    try:
        result = core.add_peer(interface, name)
        if ctx.obj.get("json"):
            _output(ctx, result)
        else:
            console.print(f"[green]Added peer {name} ({result['ip_address']})[/green]")
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
    peer_id: str = typer.Argument(..., help="Peer ID")
):
    try:
        core.remove_peer(interface, peer_id)
        if ctx.obj.get("json"):
            _output(ctx, {"status": "success", "id": peer_id})
        else:
            console.print(f"[green]Removed peer {peer_id}[/green]")
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("list")
def peer_list(ctx: typer.Context, interface: str | None = typer.Option(None, help="Filter by interface")):
    try:
        peers = db.list_peers(interface)
        if ctx.obj.get("json"):
            _output(ctx, _public_peer_rows(peers))
        else:
            data = [dict(p) for p in peers]
            table = Table(title="WireGuard Peers")
            table.add_column("ID")
            table.add_column("Interface")
            table.add_column("Name")
            table.add_column("IP Address")
            table.add_column("Created At")
            for p in data:
                table.add_row(p["id"], p["interface"], p["name"], p["ip_address"], p["created_at"])
            out_console.print(table)
    except WgplException as e:
        console.print(f"[red]WGPL Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error: {e}[/red]")
        sys.exit(1)

@peer_app.command("config")
def peer_config(
    ctx: typer.Context, 
    peer_id: str = typer.Argument(...),
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
    peer_id: str = typer.Argument(...),
    allowed_ips: str = typer.Option("0.0.0.0/0", help="AllowedIPs for the client"),
    keepalive: int = typer.Option(25, help="PersistentKeepalive interval")
):
    try:
        _validate_allowed_ips(allowed_ips)
        qr = core.get_peer_qr(peer_id, allowed_ips=allowed_ips, keepalive=keepalive)
        if ctx.obj.get("json"):
            _output(ctx, {"qr": qr})
        else:
            print(qr) # print to stdout
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
