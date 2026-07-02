import ipaddress
import uuid
import datetime
import qrcode
import io
import sqlite3

from . import db
from . import wireguard
from .exceptions import (
    AmbiguousPeerIdError,
    InterfaceNotFoundError,
    PeerNotFoundError,
    NoAvailableIpsError,
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

def _get_next_available_ip(interface_name: str, conn: sqlite3.Connection) -> str:
    """Calculates the next available IP address in the interface's pool."""
    iface = db.get_interface(interface_name, conn=conn)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_name} not found")
        
    network = ipaddress.IPv4Network(iface['address_pool'], strict=False)
    
    # Get all used IPs
    peers = db.list_peers(interface_name, conn=conn)
    used_ips = {peer['ip_address'] for peer in peers}
    
    # Typically .1 is the server itself
    try:
        used_ips.add(str(network[1]))
    except IndexError:
        # If the network prefix is /32 or /31, there might not be a network[1].
        # In this case, we just proceed as there is no gateway IP to reserve.
        pass
    
    # Find the first available IP using a fast generator expression
    available = next((str(ip) for ip in network.hosts() if str(ip) not in used_ips), None)
    
    if available:
        return available
        
    raise NoAvailableIpsError(f"No available IPs in pool {iface['address_pool']}")

def add_peer(interface_name: str, peer_name: str) -> dict[str, str]:
    """
    Creates a new peer, allocates an IP, generates keys and saves it to the DB.
    Returns a dictionary with the peer's essential information.
    """
    # 1. Database Transaction (SSOT)
    with db.transaction() as conn:
        ip_address = _get_next_available_ip(interface_name, conn)
            
        keypair = wireguard.generate_keypair()
        preshared_key = wireguard.generate_preshared_key()
        
        peer_id = str(uuid.uuid4())
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Domain exceptions (like PeerAlreadyExistsError) are raised by db.py directly
        db.add_peer(
            id=peer_id,
            interface=interface_name,
            name=peer_name,
            ip_address=ip_address,
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            preshared_key=preshared_key,
            created_at=created_at,
            conn=conn
        )
    
    # No auto-sync here. The DB is the SSOT. Users must run `wgpl apply` to sync state to the OS.
    
    return {
        "id": peer_id,
        "name": peer_name,
        "ip_address": ip_address,
        "public_key": keypair.public_key
    }

def remove_peer(interface_name: str, peer_id: str) -> None:
    """Removes a peer from the database given its ID and interface."""
    canonical_id = resolve_peer_ref(peer_id, interface_name)
    with db.transaction() as conn:
        peer = db.get_peer(canonical_id, conn=conn)
        if not peer:
            raise PeerNotFoundError(f"Peer {peer_id} not found")

        if peer['interface'] != interface_name:
            raise ValueError(f"Peer {peer_id} does not belong to interface {interface_name}")

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
        "# DNS = ... (optional)",
        "",
        "[Peer]",
        f"PublicKey = {iface['public_key']}"
    ]
    
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
