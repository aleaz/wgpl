import ipaddress
import uuid
import datetime
import qrcode
import io
import sqlite3
import sys
import os
import shutil

from . import db
from .db import UNSET, UnsetType
from . import wireguard
from .exceptions import (
    AmbiguousPeerIdError,
    InterfaceNotFoundError,
    InvalidDnsError,
    InvalidPeerIpError,
    IpAlreadyInUseError,
    NoAvailableIpsError,
    NoUpdateFieldsError,
    PeerAlreadyExistsError,
    PeerInterfaceMismatchError,
    PeerNotFoundError,
    PeersOutsidePoolError,
    WgplException,
)

_MIN_PEER_ID_PREFIX_LEN = 4
_PEER_ID_HEX_LEN = 32


def _normalize_peer_ref(ref: str) -> str:
    """Return lowercase hex ID without hyphens."""
    return ref.replace("-", "").lower()


def _format_peer_id_short(peer_id: str) -> str:
    """Return the 12-char hex prefix shown in peer list tables."""
    return _normalize_peer_ref(peer_id)[:12]


def resolve_peer_ref(ref: str, interface: str | None = None) -> str:
    """Resolve a peer reference (full UUID or unique hex prefix) to canonical UUID."""
    normalized = _normalize_peer_ref(ref)

    if not normalized or not all(c in "0123456789abcdef" for c in normalized):
        raise PeerNotFoundError(f"Peer {ref} not found")

    if len(normalized) == _PEER_ID_HEX_LEN:
        matches = db.find_peers_by_id_prefix(normalized, interface)
        exact = [peer for peer in matches if _normalize_peer_ref(peer["id"]) == normalized]
        if len(exact) == 1:
            return str(exact[0]["id"])
        if len(exact) > 1:
            raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, exact))

    if len(normalized) < _MIN_PEER_ID_PREFIX_LEN:
        raise PeerNotFoundError(f"Peer {ref} not found")

    matches = db.find_peers_by_id_prefix(normalized, interface)
    if not matches:
        raise PeerNotFoundError(f"Peer {ref} not found")
    if len(matches) == 1:
        return str(matches[0]["id"])
    raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, matches))


def _ambiguous_peer_message(ref: str, matches: list[sqlite3.Row]) -> str:
    candidates = ", ".join(
        f"{_format_peer_id_short(peer['id'])} ({peer['name']})" for peer in matches
    )
    return f"Peer ID prefix '{ref}' is ambiguous. Matches: {candidates}"


def validate_dns(value: str) -> str:
    """Validate and normalize a DNS server list for WireGuard client config."""
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts:
        raise InvalidDnsError("DNS value cannot be empty")

    normalized: list[str] = []
    for part in parts:
        try:
            ipaddress.ip_address(part)
        except ValueError as exc:
            raise InvalidDnsError(f"Invalid DNS address '{part}'") from exc
        normalized.append(part)
    return ", ".join(normalized)


def add_interface(
    name: str,
    endpoint: str,
    public_key: str,
    address_pool: str,
    port: int = 51820,
    dns: str | None = None,
) -> dict[str, str | int | None]:
    """Register a WireGuard interface in the database."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    try:
        normalized_pool = str(ipaddress.IPv4Network(address_pool, strict=False))
    except ValueError as exc:
        raise ValueError(f"Invalid address pool '{address_pool}'") from exc

    normalized_dns = validate_dns(dns) if dns is not None else None
    db.add_interface(
        name, endpoint, public_key, normalized_pool, port, dns=normalized_dns
    )

    result: dict[str, str | int | None] = {
        "name": name,
        "endpoint": endpoint,
        "port": port,
        "public_key": public_key,
        "address_pool": normalized_pool,
    }
    if normalized_dns is not None:
        result["dns"] = normalized_dns
    return result


def remove_interface(name: str) -> None:
    """Remove an interface and all associated peers from the database."""
    db.remove_interface(name)


def _effective_peer_dns(peer: sqlite3.Row, iface: sqlite3.Row) -> str | None:
    """Return peer DNS override or interface default."""
    peer_dns = peer["dns"]
    if peer_dns:
        return str(peer_dns)
    iface_dns = iface["dns"]
    if iface_dns:
        return str(iface_dns)
    return None


def _pool_used_ips(
    interface_name: str,
    conn: sqlite3.Connection,
    exclude_peer_id: str | None = None,
) -> tuple[ipaddress.IPv4Network, set[str]]:
    """Return the interface pool network and all reserved/used host IPs."""
    iface = db.get_interface(interface_name, conn=conn)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_name} not found")

    network = ipaddress.IPv4Network(iface["address_pool"], strict=False)
    used_ips = {peer["ip_address"] for peer in db.list_peers(interface_name, conn=conn)}

    if exclude_peer_id:
        peer = db.get_peer(exclude_peer_id, conn=conn)
        if peer:
            used_ips.discard(peer["ip_address"])

    try:
        used_ips.add(str(network[1]))
    except IndexError:
        pass

    return network, used_ips


def _validate_peer_ip_in_pool(ip: str, network: ipaddress.IPv4Network) -> None:
    """Raise if ip is invalid, outside the pool, or reserved for the gateway."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise InvalidPeerIpError(f"Invalid IP address '{ip}'") from exc

    host_ips = {str(host) for host in network.hosts()}
    if ip not in host_ips:
        raise InvalidPeerIpError(f"IP {ip} is not a host in pool {network}")

    try:
        if ip == str(network[1]):
            raise InvalidPeerIpError(f"IP {ip} is reserved for the interface gateway")
    except IndexError:
        pass


def _validate_requested_peer_ip(ip: str, network: ipaddress.IPv4Network, used_ips: set[str]) -> None:
    """Raise if ip is invalid, outside the pool, reserved, or already used."""
    _validate_peer_ip_in_pool(ip, network)

    if ip in used_ips:
        raise IpAlreadyInUseError(f"IP {ip} is already assigned in this interface")


def allocate_peer_ip(
    interface_name: str,
    conn: sqlite3.Connection,
    requested: str | None = None,
    exclude_peer_id: str | None = None,
) -> str:
    """Allocate the next free IP or validate a requested IP within the interface pool."""
    network, used_ips = _pool_used_ips(interface_name, conn, exclude_peer_id=exclude_peer_id)

    if requested is None:
        available = next((str(ip) for ip in network.hosts() if str(ip) not in used_ips), None)
        if available:
            return available
        raise NoAvailableIpsError(f"No available IPs in pool {network}")

    _validate_requested_peer_ip(requested, network, used_ips)
    return requested


def add_peer(
    interface_name: str,
    peer_name: str,
    ip_address: str | None = None,
    dns: str | None = None,
) -> dict[str, str | None]:
    """
    Creates a new peer, allocates an IP, generates keys and saves it to the DB.
    Returns a dictionary with the peer's essential information.
    """
    normalized_dns = validate_dns(dns) if dns is not None else None

    with db.transaction() as conn:
        allocated_ip = allocate_peer_ip(interface_name, conn, ip_address)

        keypair = wireguard.generate_keypair()
        preshared_key = wireguard.generate_preshared_key()

        peer_id = str(uuid.uuid4())
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        db.add_peer(
            id=peer_id,
            interface=interface_name,
            name=peer_name,
            ip_address=allocated_ip,
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            preshared_key=preshared_key,
            created_at=created_at,
            dns=normalized_dns,
            conn=conn,
        )

        iface = db.get_interface(interface_name, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {interface_name} not found")

    effective_dns = normalized_dns or (str(iface["dns"]) if iface["dns"] else None)

    return {
        "id": peer_id,
        "name": peer_name,
        "ip_address": allocated_ip,
        "public_key": keypair.public_key,
        "dns": effective_dns,
    }

def remove_peer(interface_name: str, peer_id: str) -> None:
    """Removes a peer from the database given its ID and interface."""
    canonical_id = resolve_peer_ref(peer_id, interface_name)
    with db.transaction() as conn:
        peer = db.get_peer(canonical_id, conn=conn)
        if not peer:
            raise PeerNotFoundError(f"Peer {peer_id} not found")

        if peer['interface'] != interface_name:
            raise PeerInterfaceMismatchError(
                f"Peer {peer_id} does not belong to interface {interface_name}"
            )

        db.remove_peer(canonical_id, conn=conn)

    # No auto-sync here. The DB is the SSOT. Users must run `wgpl apply` to sync state to the OS.

def get_peer_config(peer_id: str, allowed_ips: str = "0.0.0.0/0", keepalive: int = 25) -> str:
    """Generates the WireGuard client configuration file (.conf format) in plain text."""
    canonical_id = resolve_peer_ref(peer_id)
    peer = db.get_peer(canonical_id)
    if not peer:
        raise PeerNotFoundError(f"Peer {peer_id} not found")
        
    iface = db.get_interface(peer['interface'])
    if not iface:
        raise InterfaceNotFoundError(f"Interface {peer['interface']} not found")
        
    network = ipaddress.IPv4Network(iface['address_pool'], strict=False)

    config_lines = [
        "[Interface]",
        f"PrivateKey = {peer['private_key']}",
        f"Address = {peer['ip_address']}/{network.prefixlen}",
    ]

    effective_dns = _effective_peer_dns(peer, iface)
    if effective_dns:
        config_lines.append(f"DNS = {effective_dns}")

    config_lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {iface['public_key']}"
    ])
    
    if peer['preshared_key']:
        config_lines.append(f"PresharedKey = {peer['preshared_key']}")
        
    config_lines.extend([
        f"Endpoint = {iface['endpoint']}:{iface['port']}",
        f"AllowedIPs = {allowed_ips}",
        f"PersistentKeepalive = {keepalive}",
        ""
    ])
    
    return "\n".join(config_lines)

def get_peer_qr(peer_id: str, allowed_ips: str = "0.0.0.0/0", keepalive: int = 25) -> str:
    """Generates an ASCII-art QR code for the given peer configuration."""
    config = get_peer_config(peer_id, allowed_ips=allowed_ips, keepalive=keepalive)
    qr = qrcode.QRCode()
    qr.add_data(config)
    f = io.StringIO()
    qr.print_ascii(out=f, invert=True)
    f.seek(0)
    return f.read()

def get_peer_qr_png_bytes(peer_id: str, allowed_ips: str = "0.0.0.0/0", keepalive: int = 25) -> bytes:
    """Generates a PNG QR code image for the given peer configuration."""
    config = get_peer_config(peer_id, allowed_ips=allowed_ips, keepalive=keepalive)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(config)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer)
    return buffer.getvalue()

def get_interface_config(interface_name: str) -> str:
    """Generates the declarative config string for the server interface."""
    iface = db.get_interface(interface_name)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_name} not found")
        
    peers = db.list_peers(interface_name)
    
    conf_lines = []
    
    for peer in peers:
        conf_lines.append("[Peer]")
        conf_lines.append(f"PublicKey = {peer['public_key']}")
        if peer['preshared_key']:
            conf_lines.append(f"PresharedKey = {peer['preshared_key']}")
        conf_lines.append(f"AllowedIPs = {peer['ip_address']}/32")
        conf_lines.append("")
        
    return "\n".join(conf_lines)

def sync_interface(interface_name: str) -> None:
    """Syncs the WireGuard interface with the DB state declaratively using syncconf."""
    conf_content = get_interface_config(interface_name)
    wireguard.syncconf(interface_name, conf_content)


def _interface_row_to_dict(iface: sqlite3.Row) -> dict[str, str | int | None]:
    return {
        "name": iface["name"],
        "endpoint": iface["endpoint"],
        "port": iface["port"],
        "public_key": iface["public_key"],
        "address_pool": iface["address_pool"],
        "dns": iface["dns"],
    }


def validate_peers_in_pool(
    interface_name: str,
    pool_cidr: str,
    conn: sqlite3.Connection,
) -> None:
    """Raise PeersOutsidePoolError if any peer IP is invalid in the given pool."""
    network = ipaddress.IPv4Network(pool_cidr, strict=False)
    conflicts: list[dict[str, str]] = []

    for peer in db.list_peers(interface_name, conn=conn):
        ip = str(peer["ip_address"])
        try:
            _validate_peer_ip_in_pool(ip, network)
        except InvalidPeerIpError as exc:
            conflicts.append({"name": str(peer["name"]), "ip_address": ip, "detail": str(exc)})

    if conflicts:
        raise PeersOutsidePoolError(interface_name, conflicts)


def update_interface(
    name: str,
    *,
    endpoint: str | None = None,
    port: int | None = None,
    public_key: str | None = None,
    address_pool: str | None = None,
    dns: str | None = None,
    clear_dns: bool = False,
) -> dict[str, str | int | list[str] | None]:
    """Update interface fields. Returns the updated row and operational hints."""
    if clear_dns and dns is not None:
        raise ValueError("Cannot set both dns and clear_dns")

    has_field = any(v is not None for v in (endpoint, port, public_key, address_pool, dns))
    if not has_field and not clear_dns:
        raise NoUpdateFieldsError("No fields provided to update")

    hints: list[str] = []
    if endpoint is not None:
        hints.append("re_export_clients")
    if port is not None:
        hints.append("re_export_clients")
    if public_key is not None:
        hints.append("re_export_clients")
    if address_pool is not None:
        hints.append("re_export_clients")
    if dns is not None or clear_dns:
        hints.append("re_export_clients")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    normalized_pool: str | None = None
    if address_pool is not None:
        try:
            normalized_pool = str(ipaddress.IPv4Network(address_pool, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid address pool '{address_pool}'") from exc

    normalized_dns: str | None | UnsetType = UNSET
    if clear_dns:
        normalized_dns = None
    elif dns is not None:
        normalized_dns = validate_dns(dns)

    with db.transaction() as conn:
        iface = db.get_interface(name, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {name} not found")

        if normalized_pool is not None and normalized_pool != iface["address_pool"]:
            validate_peers_in_pool(name, normalized_pool, conn)

        db.update_interface(
            name,
            endpoint=endpoint if endpoint is not None else UNSET,
            port=port if port is not None else UNSET,
            public_key=public_key if public_key is not None else UNSET,
            address_pool=normalized_pool if normalized_pool is not None else UNSET,
            dns=normalized_dns,
            conn=conn,
        )

        updated = db.get_interface(name, conn=conn)
        if not updated:
            raise InterfaceNotFoundError(f"Interface {name} not found")

    result: dict[str, str | int | list[str] | None] = dict(_interface_row_to_dict(updated))
    result["hints"] = list(dict.fromkeys(hints))
    return result


def update_peer(
    interface_name: str,
    peer_ref: str,
    *,
    name: str | None = None,
    ip_address: str | None = None,
    dns: str | None = None,
    clear_dns: bool = False,
) -> dict[str, str | list[str] | None]:
    """Update peer fields. Returns safe peer data and operational hints."""
    if clear_dns and dns is not None:
        raise ValueError("Cannot set both dns and clear_dns")

    has_field = any(v is not None for v in (name, ip_address, dns))
    if not has_field and not clear_dns:
        raise NoUpdateFieldsError("No fields provided to update")

    canonical_id = resolve_peer_ref(peer_ref, interface_name)
    hints: list[str] = []

    if ip_address is not None:
        hints.extend(["apply_server", "re_export_client"])
    if dns is not None or clear_dns:
        hints.append("re_export_client")

    normalized_dns: str | None | UnsetType = UNSET
    if clear_dns:
        normalized_dns = None
    elif dns is not None:
        normalized_dns = validate_dns(dns)

    with db.transaction() as conn:
        peer = db.get_peer(canonical_id, conn=conn)
        if not peer:
            raise PeerNotFoundError(f"Peer {peer_ref} not found")
        if peer["interface"] != interface_name:
            raise PeerInterfaceMismatchError(
                f"Peer {peer_ref} does not belong to interface {interface_name}"
            )

        validated_ip: str | UnsetType = UNSET
        if ip_address is not None:
            validated_ip = allocate_peer_ip(
                interface_name,
                conn,
                ip_address,
                exclude_peer_id=canonical_id,
            )

        try:
            db.update_peer(
                canonical_id,
                name=name if name is not None else UNSET,
                ip_address=validated_ip,
                dns=normalized_dns,
                conn=conn,
            )
        except PeerAlreadyExistsError:
            raise

        updated = db.get_peer(canonical_id, conn=conn)
        if not updated:
            raise PeerNotFoundError(f"Peer {peer_ref} not found")

        iface = db.get_interface(interface_name, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {interface_name} not found")

    effective_dns = _effective_peer_dns(updated, iface)
    return {
        "id": str(updated["id"]),
        "name": str(updated["name"]),
        "ip_address": str(updated["ip_address"]),
        "dns": effective_dns,
        "dns_override": updated["dns"],
        "hints": list(dict.fromkeys(hints)),
    }


def validate_state(interface: str | None = None) -> dict[str, str | list[dict[str, str]]]:
    """Validate DB consistency without mutating state."""
    issues: list[dict[str, str]] = []

    if interface is not None:
        iface = db.get_interface(interface)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {interface} not found")
        interfaces = [iface]
    else:
        interfaces = db.list_interfaces()

    for iface in interfaces:
        iface_name = str(iface["name"])
        pool = str(iface["address_pool"])
        network = ipaddress.IPv4Network(pool, strict=False)

        if iface["dns"]:
            try:
                validate_dns(str(iface["dns"]))
            except InvalidDnsError as exc:
                issues.append({
                    "interface": iface_name,
                    "peer": "",
                    "code": "invalid_dns",
                    "detail": f"Interface DNS: {exc}",
                })

        for peer in db.list_peers(iface_name):
            peer_name = str(peer["name"])
            ip = str(peer["ip_address"])
            try:
                _validate_peer_ip_in_pool(ip, network)
            except InvalidPeerIpError as exc:
                issues.append({
                    "interface": iface_name,
                    "peer": peer_name,
                    "code": "ip_outside_pool",
                    "detail": str(exc),
                })

            if peer["dns"]:
                try:
                    validate_dns(str(peer["dns"]))
                except InvalidDnsError as exc:
                    issues.append({
                        "interface": iface_name,
                        "peer": peer_name,
                        "code": "invalid_dns",
                        "detail": str(exc),
                    })

    status = "ok" if not issues else "error"
    return {"status": status, "issues": issues}

# --- Database Dump & Restore ---

def dump_database() -> None:
    """Dumps the SQLite database to stdout as a logical SQL script."""
    sys.stderr.write("Hint: Redirect this output to a file (e.g. wgpl db dump > backup.sql).\n")
    sys.stderr.write("      Ensure the resulting file has secure permissions (chmod 600) or encrypt it.\n\n")
    sys.stderr.flush()
    with db.get_db() as conn:
        for line in conn.iterdump():
            sys.stdout.write(f"{line}\n")
    sys.stdout.flush()

def restore_database(sql_script: str) -> None:
    """
    Safely restores the database from a SQL script.
    Uses a temporary file to avoid corruption. If successful, replaces the live DB atomically
    and cleans up WAL files.
    """
    db_path = db.get_db_path()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.bak.{timestamp}"
    tmp_path = f"{db_path}.tmp"
    
    # 1. Ensure tmp file does not exist
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
        
    # 2. Create tmp db with 0o600
    fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    
    # 3. Execute script in tmp DB
    try:
        tmp_conn = sqlite3.connect(tmp_path)
        tmp_conn.executescript(sql_script)
        tmp_conn.close()
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise WgplException(f"Failed to restore database from script: {e}")
        
    # 4. Backup current db if it exists
    if os.path.exists(db_path):
        shutil.copy2(db_path, backup_path)
        
    # 5. Atomic replacement and WAL cleanup
    for suffix in ['-wal', '-shm']:
        wal_file = f"{db_path}{suffix}"
        if os.path.exists(wal_file):
            try:
                os.remove(wal_file)
            except OSError:
                pass
                
    # Atomic rename on POSIX
    os.rename(tmp_path, db_path)
