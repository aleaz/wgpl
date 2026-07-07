import ipaddress
import uuid
import datetime
import qrcode
import io
import sqlite3
import re
from collections.abc import Mapping
from typing import Any

from . import db
from .db import UNSET, UnsetType
from . import integrity
from . import wireformat
from . import wireguard
from .audit import (
    _audit_interface_event,
    _audit_peer_from_row,
    audit_event_to_dict,
    list_interface_audit_history,
    list_peer_audit_history,
)
from .ipam import _reclaim_inactive_peer_slots, allocate_peer_ip
from .refs import (
    PeerResolvePolicy,
    get_interface_by_ref,
    resolve_interface_ref,
    resolve_peer_ref,
)
from .restore import dump_database, restore_database
from .consistency import assert_database_valid, validate_state
from .validators import (
    validate_allowed_ips,
    validate_dns,
    validate_endpoint,
    validate_peer_name,
    validate_public_key,
)
from .exceptions import (
    InterfaceHasPeersError,
    InterfaceNotFoundError,
    NoUpdateFieldsError,
    PeerAlreadyExistsError,
    PeerInterfaceMismatchError,
    PeerNotFoundError,
)

__all__ = [
    "PeerResolvePolicy",
    "add_interface",
    "add_peer",
    "allocate_peer_ip",
    "assert_database_valid",
    "audit_event_to_dict",
    "dump_database",
    "ensure_database",
    "get_effective_dns",
    "get_interface_by_ref",
    "get_interface_config",
    "get_peer_config",
    "get_peer_qr",
    "get_peer_qr_png_bytes",
    "get_peer_status",
    "interface_dns_map",
    "list_interface_audit_history",
    "list_interfaces",
    "list_peer_audit_history",
    "list_peers",
    "peer_row_to_public_dict",
    "prune_peers",
    "remove_interface",
    "remove_peer",
    "resolve_interface_ref",
    "resolve_peer_ref",
    "restore_database",
    "sync_interface",
    "update_interface",
    "update_peer",
    "validate_allowed_ips",
    "validate_dns",
    "validate_endpoint",
    "validate_peer_name",
    "validate_public_key",
    "validate_state",
]


def _is_peer_active(peer: sqlite3.Row | Mapping[str, object]) -> bool:
    """Returns True if the peer is not soft-deleted and not expired."""
    return integrity.is_peer_active(peer)


def get_peer_status(peer: sqlite3.Row | Mapping[str, object]) -> str:
    """Return lifecycle label: Active, Expired, or Deleted."""
    deleted_at = peer["deleted_at"] if "deleted_at" in peer.keys() else None
    if deleted_at is not None:
        return "Deleted"
    if not _is_peer_active(peer):
        return "Expired"
    return "Active"


def _peer_optional_field(peer: sqlite3.Row | Mapping[str, object], field: str) -> Any:
    if isinstance(peer, sqlite3.Row):
        return peer[field] if field in peer.keys() else None
    if field in peer.keys():
        return peer[field]
    return None


def peer_row_to_public_dict(
    peer: sqlite3.Row | Mapping[str, object],
    iface_dns: dict[int, str | None] | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe peer record without private_key or preshared_key."""
    iface_dns_map = iface_dns or {}
    interface_id = int(str(peer["interface_id"]))
    peer_dns = _peer_optional_field(peer, "dns")
    if peer_dns is not None:
        peer_dns = str(peer_dns)
    created_at = peer["created_at"]
    return {
        "id": str(peer["id"]),
        "interface_id": str(interface_id),
        "name": str(peer["name"]),
        "ip_address": str(peer["ip_address"]),
        "public_key": str(peer["public_key"]),
        "created_at": str(created_at) if created_at is not None else None,
        "dns": get_effective_dns(peer_dns, iface_dns_map.get(interface_id)),
        "dns_override": peer_dns,
        "status": get_peer_status(peer),
        "expires_at": _peer_optional_field(peer, "expires_at"),
        "deleted_at": _peer_optional_field(peer, "deleted_at"),
    }


def get_effective_dns(peer_dns: str | None, iface_dns: str | None) -> str | None:
    """Return peer DNS override or interface default."""
    if peer_dns:
        return str(peer_dns)
    if iface_dns:
        return str(iface_dns)
    return None


def _peer_actual_changed_fields(
    before: sqlite3.Row,
    after: sqlite3.Row,
    candidates: list[str],
) -> dict[str, dict[str, Any]]:
    """Return candidate field names and their state diffs."""
    column_map = {
        "name": "name",
        "ip_address": "ip_address",
        "dns": "dns",
        "desc": "desc",
        "mtu": "mtu",
        "keepalive": "keepalive",
        "expires": "expires_at",
    }
    changed: dict[str, dict[str, Any]] = {}
    for field in candidates:
        column = column_map[field]
        if before[column] != after[column]:
            changed[field] = {"old": before[column], "new": after[column]}
    return changed


def _interface_actual_changed_fields(
    before: sqlite3.Row,
    after: sqlite3.Row,
    candidates: list[str],
) -> dict[str, dict[str, Any]]:
    """Return candidate interface field names and their state diffs."""
    column_map = {
        "endpoint": "endpoint",
        "port": "port",
        "public_key": "public_key",
        "address_pool": "address_pool",
        "dns": "dns",
        "desc": "desc",
        "mtu": "mtu",
        "keepalive": "keepalive",
    }
    changed: dict[str, dict[str, Any]] = {}
    for field in candidates:
        column = column_map[field]
        if before[column] != after[column]:
            changed[field] = {"old": before[column], "new": after[column]}
    return changed


def add_interface(
    name: str,
    endpoint: str,
    public_key: str,
    address_pool: str,
    port: int = 51820,
    dns: str | None = None,
    desc: str | None = None,
    mtu: int | None = None,
    keepalive: int | None = None,
) -> dict[str, Any]:
    """Register a new interface in the DB."""
    name = name.strip()
    if not name:
        raise ValueError("Interface name cannot be empty")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$", name):
        raise ValueError(
            "Interface name contains invalid characters. Must start with alphanumeric and contain only alphanumerics, hyphens, and underscores."
        )
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    endpoint = validate_endpoint(endpoint)
    public_key = validate_public_key(public_key)

    try:
        normalized_pool = str(ipaddress.IPv4Network(address_pool, strict=False))
    except ValueError as exc:
        raise ValueError(f"Invalid address pool '{address_pool}'") from exc

    normalized_dns = validate_dns(dns) if dns is not None else None
    if mtu is not None and mtu < 576:
        raise ValueError(f"MTU must be >= 576, got {mtu}")
    if keepalive is not None and not (0 <= keepalive <= 65535):
        raise ValueError(f"Keepalive must be between 0 and 65535, got {keepalive}")

    with db.transaction() as conn:
        iface_id = db.add_interface(
            name,
            endpoint,
            public_key,
            normalized_pool,
            port,
            dns=normalized_dns,
            desc=desc,
            mtu=mtu,
            keepalive=keepalive,
            conn=conn,
        )
        _audit_interface_event(
            iface_id,
            db.AuditEventType.CREATED,
            conn,
            metadata={"name": name, "port": port, "address_pool": normalized_pool},
        )

    result: dict[str, Any] = {
        "id": iface_id,
        "name": name,
        "endpoint": endpoint,
        "port": port,
        "public_key": public_key,
        "address_pool": normalized_pool,
    }
    if normalized_dns is not None:
        result["dns"] = normalized_dns
    if desc is not None:
        result["desc"] = desc
    if mtu is not None:
        result["mtu"] = mtu
    if keepalive is not None:
        result["keepalive"] = keepalive
    return result


def remove_interface(ref: str, *, force: bool = False) -> None:
    """Remove an interface and optionally all associated peers (requires --force if peers exist)."""
    with db.transaction() as conn:
        iface_id = resolve_interface_ref(ref, conn=conn)
        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {ref} not found")

        name = str(iface["name"])

        peers = db.list_peers(iface_id, conn=conn)
        if peers and not force:
            raise InterfaceHasPeersError(
                f"Interface {name} (ID {iface_id}) has {len(peers)} peer(s). "
                "Remove or prune peers first, or use --force."
            )

        for peer in peers:
            _audit_peer_from_row(
                peer,
                db.AuditEventType.CASCADE_REMOVED,
                conn,
                metadata={
                    "trigger": "interface_removed",
                    "interface": name,
                    "interface_id": iface_id,
                },
            )
        _audit_interface_event(
            iface_id,
            db.AuditEventType.REMOVED,
            conn,
            metadata={
                "name": name,
                "peer_count": len(peers),
                "forced": bool(peers and force),
            },
        )
        db.remove_interface(iface_id, conn=conn)


def ensure_database() -> None:
    """Initialize the database connection and schema."""
    db.init_db()


def list_interfaces() -> list[dict[str, Any]]:
    """Return all interfaces as plain dicts."""
    return [dict(row) for row in db.list_interfaces()]


def interface_dns_map() -> dict[int, str | None]:
    """Return interface ID to default DNS."""
    return {int(row["id"]): row["dns"] for row in db.list_interfaces()}


def list_peers(
    interface: str | None = None,
    *,
    expired_only: bool = False,
    show_all: bool = False,
) -> list[sqlite3.Row]:
    """Return peers filtered by lifecycle status for display."""
    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface, conn=conn) if interface else None
        raw_peers = db.list_peers(iface_id, conn=conn)
    peers: list[sqlite3.Row] = []
    for peer in raw_peers:
        status = get_peer_status(peer)
        if show_all:
            peers.append(peer)
        elif expired_only:
            if status == "Expired":
                peers.append(peer)
        elif status == "Active":
            peers.append(peer)
    return peers


def _effective_peer_dns(peer: sqlite3.Row, iface: sqlite3.Row) -> str | None:
    """Return peer DNS override or interface default."""
    return get_effective_dns(peer["dns"], iface["dns"])


def _effective_peer_mtu(peer: sqlite3.Row, iface: sqlite3.Row) -> int | None:
    peer_mtu = peer["mtu"]
    if peer_mtu is not None:
        return int(peer_mtu)
    iface_mtu = iface["mtu"]
    if iface_mtu is not None:
        return int(iface_mtu)
    return None


def _effective_peer_keepalive(peer: sqlite3.Row, iface: sqlite3.Row) -> int | None:
    peer_ka = peer["keepalive"]
    if peer_ka is not None:
        return int(peer_ka)
    iface_ka = iface["keepalive"]
    if iface_ka is not None:
        return int(iface_ka)
    return None


def add_peer(
    interface_name: str,
    peer_name: str,
    ip_address: str | None = None,
    dns: str | None = None,
    expires: str | None = None,
    desc: str | None = None,
    mtu: int | None = None,
    keepalive: int | None = None,
) -> dict[str, Any]:
    """
    Creates a new peer, allocates an IP, generates keys and saves it to the DB.
    Returns a dictionary with the peer's essential information.
    """
    peer_name = validate_peer_name(peer_name)
    normalized_dns = validate_dns(dns) if dns is not None else None
    if mtu is not None and mtu < 576:
        raise ValueError(f"MTU must be >= 576, got {mtu}")
    if keepalive is not None and not (0 <= keepalive <= 65535):
        raise ValueError(f"Keepalive must be between 0 and 65535, got {keepalive}")

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_name, conn=conn)
        allocated_ip = allocate_peer_ip(iface_id, conn, ip_address)

        keypair = wireguard.generate_keypair()
        preshared_key = wireguard.generate_preshared_key()

        peer_id = str(uuid.uuid4())
        _reclaim_inactive_peer_slots(
            iface_id,
            conn,
            ip=allocated_ip,
            name=peer_name,
            replaced_by_peer_id=peer_id,
        )

        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        expires_at = None
        if expires:
            expires_at = integrity.parse_future_duration(expires).isoformat()

        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface ID {iface_id} not found")

        prospective_peer: dict[str, object] = {
            "id": peer_id,
            "interface_id": iface_id,
            "name": peer_name,
            "ip_address": allocated_ip,
            "public_key": keypair.public_key,
            "preshared_key": preshared_key,
            "deleted_at": None,
            "expires_at": expires_at,
        }
        integrity.assert_peer_activation(
            prospective_peer, iface, conn=conn, exclude_peer_id=peer_id
        )

        db.add_peer(
            id=peer_id,
            interface_id=iface_id,
            name=peer_name,
            ip_address=allocated_ip,
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            preshared_key=preshared_key,
            created_at=created_at,
            dns=normalized_dns,
            expires_at=expires_at,
            desc=desc,
            mtu=mtu,
            keepalive=keepalive,
            conn=conn,
        )

        created_peer = db.get_peer(peer_id, conn=conn)
        if created_peer:
            meta: dict[str, Any] = {"has_psk": bool(preshared_key)}
            if expires_at:
                meta["expires_at"] = expires_at
            _audit_peer_from_row(
                created_peer,
                db.AuditEventType.CREATED,
                conn,
                metadata=meta or None,
            )

    effective_dns = normalized_dns or (str(iface["dns"]) if iface["dns"] else None)

    return {
        "id": peer_id,
        "name": peer_name,
        "ip_address": allocated_ip,
        "public_key": keypair.public_key,
        "dns": effective_dns,
        "desc": desc,
        "mtu": mtu,
        "keepalive": keepalive,
    }


def remove_peer(interface_ref: str, canonical_peer_id: str, hard: bool = False) -> None:
    """Removes a peer from the database. Does a soft-delete by default."""
    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_ref, conn=conn)
        peer = db.get_peer(canonical_peer_id, conn=conn)
        if not peer:
            raise PeerNotFoundError(f"Peer {canonical_peer_id} not found")

        if peer["interface_id"] != iface_id:
            raise PeerInterfaceMismatchError(
                f"Peer {canonical_peer_id} does not belong to interface {interface_ref}"
            )

        if hard:
            _audit_peer_from_row(
                peer,
                db.AuditEventType.REMOVED,
                conn,
                metadata={"hard": True},
            )
            db.hard_remove_peer(canonical_peer_id, conn=conn)
        elif peer["deleted_at"] is not None:
            return
        else:
            _audit_peer_from_row(peer, db.AuditEventType.REMOVED, conn)
            db.remove_peer(canonical_peer_id, conn=conn)


def prune_peers(interface_ref: str) -> int:
    """Physically removes all inactive peers (soft-deleted or expired) for an interface."""
    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_ref, conn=conn)
        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {interface_ref} not found")

        to_remove = [
            peer
            for peer in db.list_peers(iface_id, conn=conn)
            if not _is_peer_active(peer)
        ]
        for peer in to_remove:
            was_expired = get_peer_status(peer) == "Expired"
            _audit_peer_from_row(
                peer,
                db.AuditEventType.PRUNED,
                conn,
                metadata={
                    "was_expired": was_expired,
                    "was_soft_deleted": not was_expired,
                },
            )
            db.hard_remove_peer(peer["id"], conn=conn)
        return len(to_remove)

    # No auto-sync here. The DB is the SSOT. Users must run `wgpl apply` to sync state to the OS.


def get_peer_config(
    peer_id: str,
    allowed_ips: str = "0.0.0.0/0",
    *,
    interface_ref: str | None = None,
) -> str:
    """Generates the WireGuard client configuration file (.conf format) in plain text."""
    canonical_id = resolve_peer_ref(
        peer_id, interface_ref, policy=PeerResolvePolicy.EXPORT_SECRET
    )
    peer = db.get_peer(canonical_id)
    if not peer:
        raise PeerNotFoundError(f"Peer {peer_id} not found")

    iface = db.get_interface(peer["interface_id"])
    if not iface:
        raise InterfaceNotFoundError(f"Interface ID {peer['interface_id']} not found")

    return wireformat.build_client_config(peer, iface, allowed_ips)


def get_peer_qr(
    peer_id: str,
    allowed_ips: str = "0.0.0.0/0",
    *,
    interface_ref: str | None = None,
) -> str:
    """Generates an ASCII-art QR code for the given peer configuration."""
    config = get_peer_config(
        peer_id, allowed_ips=allowed_ips, interface_ref=interface_ref
    )
    qr = qrcode.QRCode()
    qr.add_data(config)
    f = io.StringIO()
    qr.print_ascii(out=f, invert=True)
    f.seek(0)
    return f.read()


def get_peer_qr_png_bytes(
    peer_id: str,
    allowed_ips: str = "0.0.0.0/0",
    *,
    interface_ref: str | None = None,
) -> bytes:
    """Generates a PNG QR code image for the given peer configuration."""
    config = get_peer_config(
        peer_id, allowed_ips=allowed_ips, interface_ref=interface_ref
    )
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


def get_interface_config(interface_ref: str) -> str:
    """Generates the declarative config string for the server interface."""
    iface_id = resolve_interface_ref(interface_ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_ref} not found")

    peers = db.list_peers(iface_id)
    return wireformat.build_server_config(iface, peers)


def sync_interface(interface_ref: str) -> None:
    """Syncs the WireGuard interface with the DB state declaratively using syncconf."""
    assert_database_valid(interface_ref)
    iface_id = resolve_interface_ref(interface_ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_ref} not found")
    name = str(iface["name"])
    conf_content = get_interface_config(str(iface_id))
    wireguard.syncconf(name, conf_content)


def _interface_row_to_dict(iface: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": iface["id"],
        "name": iface["name"],
        "endpoint": iface["endpoint"],
        "port": iface["port"],
        "public_key": iface["public_key"],
        "address_pool": iface["address_pool"],
        "dns": iface["dns"],
    }


def _resolve_optional(val: Any, clear: bool) -> Any | UnsetType:
    """Helper to resolve update values vs clear flags."""
    if clear:
        return None
    if val is not None:
        return val
    return UNSET


def update_interface(
    ref: str,
    *,
    endpoint: str | None = None,
    port: int | None = None,
    public_key: str | None = None,
    address_pool: str | None = None,
    dns: str | None = None,
    clear_dns: bool = False,
    desc: str | None = None,
    clear_desc: bool = False,
    mtu: int | None = None,
    clear_mtu: bool = False,
    keepalive: int | None = None,
    clear_keepalive: bool = False,
) -> dict[str, str | int | list[str] | None]:
    """Update interface fields. Returns the updated row and operational hints."""
    if clear_dns and dns is not None:
        raise ValueError("Cannot set both dns and clear_dns")
    if clear_desc and desc is not None:
        raise ValueError("Cannot set both desc and clear_desc")
    if clear_mtu and mtu is not None:
        raise ValueError("Cannot set both mtu and clear_mtu")
    if clear_keepalive and keepalive is not None:
        raise ValueError("Cannot set both keepalive and clear_keepalive")

    has_field = any(
        v is not None
        for v in (endpoint, port, public_key, address_pool, dns, desc, mtu, keepalive)
    )
    if (
        not has_field
        and not clear_dns
        and not clear_desc
        and not clear_mtu
        and not clear_keepalive
    ):
        raise NoUpdateFieldsError("No fields provided to update")

    hints: list[str] = []
    if mtu is not None or clear_mtu:
        hints.append("apply_server")
    if (
        any(
            x is not None
            for x in (endpoint, port, public_key, address_pool, dns, mtu, keepalive)
        )
        or clear_dns
        or clear_mtu
        or clear_keepalive
    ):
        if "re_export_clients" not in hints:
            hints.append("re_export_clients")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    if mtu is not None and mtu < 576:
        raise ValueError(f"MTU must be >= 576, got {mtu}")
    if keepalive is not None and not (0 <= keepalive <= 65535):
        raise ValueError(f"Keepalive must be between 0 and 65535, got {keepalive}")

    normalized_pool: str | None = None
    if address_pool is not None:
        try:
            normalized_pool = str(ipaddress.IPv4Network(address_pool, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid address pool '{address_pool}'") from exc

    if endpoint is not None:
        endpoint = validate_endpoint(endpoint)
    if public_key is not None:
        public_key = validate_public_key(public_key)

    normalized_dns: str | None | UnsetType = UNSET
    if clear_dns:
        normalized_dns = None
    elif dns is not None:
        normalized_dns = validate_dns(dns)

    normalized_desc: str | None | UnsetType = UNSET
    if clear_desc:
        normalized_desc = None
    elif desc is not None:
        normalized_desc = desc

    normalized_mtu: int | None | UnsetType = UNSET
    if clear_mtu:
        normalized_mtu = None
    elif mtu is not None:
        normalized_mtu = mtu

    normalized_keepalive: int | None | UnsetType = UNSET
    if clear_keepalive:
        normalized_keepalive = None
    elif keepalive is not None:
        normalized_keepalive = keepalive

    changed_fields: list[str] = []
    if endpoint is not None:
        changed_fields.append("endpoint")
    if port is not None:
        changed_fields.append("port")
    if public_key is not None:
        changed_fields.append("public_key")
    if address_pool is not None:
        changed_fields.append("address_pool")
    if dns is not None or clear_dns:
        changed_fields.append("dns")
    if desc is not None or clear_desc:
        changed_fields.append("desc")
    if mtu is not None or clear_mtu:
        changed_fields.append("mtu")
    if keepalive is not None or clear_keepalive:
        changed_fields.append("keepalive")

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(ref, conn=conn)
        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {ref} not found")

        name = str(iface["name"])

        if normalized_pool is not None and normalized_pool != iface["address_pool"]:
            integrity.validate_non_deleted_peers_in_pool(
                name,
                normalized_pool,
                conn,
                resolve_interface_ref=resolve_interface_ref,
            )

        db.update_interface(
            iface_id,
            endpoint=endpoint if endpoint is not None else UNSET,
            port=port if port is not None else UNSET,
            public_key=public_key if public_key is not None else UNSET,
            address_pool=normalized_pool if normalized_pool is not None else UNSET,
            dns=normalized_dns,
            desc=normalized_desc,
            mtu=normalized_mtu,
            keepalive=normalized_keepalive,
            conn=conn,
        )

        updated = db.get_interface(iface_id, conn=conn)
        if not updated:
            raise InterfaceNotFoundError(
                f"Interface ID {iface_id} not found after update"
            )

        actual_changes = _interface_actual_changed_fields(
            iface, updated, changed_fields
        )
        if actual_changes:
            _audit_interface_event(
                iface_id,
                db.AuditEventType.UPDATED,
                conn,
                metadata={"name": name, "fields": actual_changes},
            )

    result: dict[str, str | int | list[str] | None] = dict(
        _interface_row_to_dict(updated)
    )
    result["hints"] = list(dict.fromkeys(hints))
    return result


def update_peer(
    interface_ref: str,
    peer_ref: str,
    *,
    active_only: bool = True,
    name: str | None = None,
    ip_address: str | None = None,
    dns: str | None = None,
    clear_dns: bool = False,
    desc: str | None = None,
    clear_desc: bool = False,
    mtu: int | None = None,
    clear_mtu: bool = False,
    keepalive: int | None = None,
    clear_keepalive: bool = False,
    expires: str | None = None,
    clear_expires: bool = False,
) -> dict[str, Any]:
    """Update peer fields. Returns safe peer data and operational hints."""
    if name is not None:
        name = validate_peer_name(name)
    if clear_dns and dns is not None:
        raise ValueError("Cannot set both dns and clear_dns")
    if clear_desc and desc is not None:
        raise ValueError("Cannot set both desc and clear_desc")
    if clear_mtu and mtu is not None:
        raise ValueError("Cannot set both mtu and clear_mtu")
    if clear_keepalive and keepalive is not None:
        raise ValueError("Cannot set both keepalive and clear_keepalive")
    if clear_expires and expires is not None:
        raise ValueError("Cannot set both expires and clear_expires")

    has_field = any(
        v is not None for v in (name, ip_address, dns, desc, mtu, keepalive, expires)
    )
    if (
        not has_field
        and not clear_dns
        and not clear_desc
        and not clear_mtu
        and not clear_keepalive
        and not clear_expires
    ):
        raise NoUpdateFieldsError("No fields provided to update")

    hints: list[str] = []
    if ip_address is not None:
        hints.append("apply_server")
    if (
        any(x is not None for x in (ip_address, dns, mtu, keepalive))
        or clear_dns
        or clear_mtu
        or clear_keepalive
    ):
        hints.append("re_export_client")

    if mtu is not None and mtu < 576:
        raise ValueError(f"MTU must be >= 576, got {mtu}")
    if keepalive is not None and not (0 <= keepalive <= 65535):
        raise ValueError(f"Keepalive must be between 0 and 65535, got {keepalive}")

    normalized_dns = _resolve_optional(validate_dns(dns) if dns else None, clear_dns)
    normalized_desc = _resolve_optional(desc, clear_desc)
    normalized_mtu = _resolve_optional(mtu, clear_mtu)
    normalized_keepalive = _resolve_optional(keepalive, clear_keepalive)

    normalized_expires = _resolve_optional(
        integrity.parse_future_duration(expires).isoformat() if expires else None,
        clear_expires,
    )

    changed_fields: list[str] = []
    if name is not None:
        changed_fields.append("name")
    if ip_address is not None:
        changed_fields.append("ip_address")
    if dns is not None or clear_dns:
        changed_fields.append("dns")
    if desc is not None or clear_desc:
        changed_fields.append("desc")
    if mtu is not None or clear_mtu:
        changed_fields.append("mtu")
    if keepalive is not None or clear_keepalive:
        changed_fields.append("keepalive")
    if expires is not None or clear_expires:
        changed_fields.append("expires")

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_ref, conn=conn)
        resolve_policy = (
            PeerResolvePolicy.MUTATE_INACTIVE
            if not active_only
            else PeerResolvePolicy.READ_ONLY
        )
        canonical_id = resolve_peer_ref(
            peer_ref, str(iface_id), policy=resolve_policy, conn=conn
        )
        peer = db.get_peer(canonical_id, conn=conn)
        if not peer:
            raise PeerNotFoundError(f"Peer {peer_ref} not found")
        if peer["interface_id"] != iface_id:
            raise PeerInterfaceMismatchError(
                f"Peer {peer_ref} does not belong to interface {interface_ref}"
            )
        before = peer

        validated_ip: str | UnsetType = UNSET
        slot_ip: str | None = None
        if ip_address is not None:
            validated_ip = allocate_peer_ip(
                iface_id,
                conn,
                ip_address,
                exclude_peer_id=canonical_id,
            )
            slot_ip = validated_ip

        slot_name = name
        if slot_ip is not None or slot_name is not None:
            _reclaim_inactive_peer_slots(
                iface_id,
                conn,
                ip=slot_ip,
                name=slot_name,
                replaced_by_peer_id=canonical_id,
            )

        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface ID {iface_id} not found")

        prospective_peer = dict(peer)
        if name is not None:
            prospective_peer["name"] = name
        if ip_address is not None:
            prospective_peer["ip_address"] = str(validated_ip)
        if normalized_expires is not UNSET:
            prospective_peer["expires_at"] = normalized_expires
        integrity.assert_peer_activation(
            prospective_peer,
            iface,
            conn=conn,
            exclude_peer_id=canonical_id,
        )

        try:
            db.update_peer(
                canonical_id,
                name=name if name is not None else UNSET,
                ip_address=validated_ip,
                dns=normalized_dns,
                desc=normalized_desc,
                mtu=normalized_mtu,
                keepalive=normalized_keepalive,
                expires_at=normalized_expires,
                conn=conn,
            )
        except PeerAlreadyExistsError:
            raise

        updated = db.get_peer(canonical_id, conn=conn)
        if not updated:
            raise PeerNotFoundError(f"Peer {peer_ref} not found")

        actual_changes = _peer_actual_changed_fields(before, updated, changed_fields)
        if actual_changes:
            _audit_peer_from_row(
                updated,
                db.AuditEventType.UPDATED,
                conn,
                metadata={"fields": actual_changes},
            )

    effective_dns = _effective_peer_dns(updated, iface)
    return {
        "id": str(updated["id"]),
        "name": str(updated["name"]),
        "ip_address": str(updated["ip_address"]),
        "dns": effective_dns,
        "dns_override": updated["dns"],
        "desc": updated["desc"],
        "mtu": _effective_peer_mtu(updated, iface),
        "mtu_override": updated["mtu"],
        "keepalive": _effective_peer_keepalive(updated, iface),
        "keepalive_override": updated["keepalive"],
        "expires_at": updated["expires_at"],
        "hints": list(dict.fromkeys(hints)),
    }
