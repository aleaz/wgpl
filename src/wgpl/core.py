import re
import base64
import glob
import ipaddress
import uuid
import datetime
import qrcode
import io
import sqlite3
import os
import shutil
import json
from collections.abc import Mapping
from typing import Any, cast

from . import db
from .db import UNSET, UnsetType
from . import integrity
from . import wireformat
from . import wireguard
from .exceptions import (
    AmbiguousInterfaceError,
    AmbiguousPeerIdError,
    InterfaceHasPeersError,
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

_MAX_EXEC_CMD_LEN = 2_048


def _sanitize_exec_cmd(exec_cmd: str) -> str:
    """Sanitize exec_cmd for storing into audit metadata.

    We do not attempt secret redaction here; instead we prevent audit log
    injection (control characters) and keep the payload bounded.
    """
    # Replace common control chars with spaces to avoid log/terminal injection.
    sanitized = re.sub(r"[\r\n\t]+", " ", str(exec_cmd))
    # Drop other non-printable characters.
    sanitized = "".join(ch for ch in sanitized if ch.isprintable())
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    if len(sanitized) > _MAX_EXEC_CMD_LEN:
        sanitized = sanitized[:_MAX_EXEC_CMD_LEN] + "..."
    return sanitized


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


def _peer_optional_field(
    peer: sqlite3.Row | Mapping[str, object], field: str
) -> Any:
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


def _audit_peer_from_row(
    peer: sqlite3.Row,
    event_type: db.AuditEventType,
    conn: sqlite3.Connection,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata_with_context = dict(metadata) if metadata else {}
    exec_cmd = os.environ.get("WGPL_EXEC_CMD")
    if exec_cmd:
        metadata_with_context["exec_cmd"] = _sanitize_exec_cmd(exec_cmd)

    db.append_audit_event(
        entity_type=db.AuditEntityType.PEER,
        entity_id=str(peer["id"]),
        event_type=event_type,
        interface=str(peer["interface_id"]),
        name=str(peer["name"]),
        ip_address=str(peer["ip_address"]),
        public_key=str(peer["public_key"]),
        metadata=metadata_with_context or None,
        conn=conn,
    )


def _audit_interface_event(
    interface_id: int,
    event_type: db.AuditEventType,
    conn: sqlite3.Connection,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Create an audit trail event for an interface action."""
    metadata_with_context = dict(metadata) if metadata else {}
    exec_cmd = os.environ.get("WGPL_EXEC_CMD")
    if exec_cmd:
        metadata_with_context["exec_cmd"] = _sanitize_exec_cmd(exec_cmd)

    iface = db.get_interface(interface_id, conn=conn)
    name = iface["name"] if iface else str(interface_id)
    db.append_audit_event(
        entity_type=db.AuditEntityType.INTERFACE,
        entity_id=str(interface_id),
        event_type=event_type,
        interface=name,
        name=name,
        metadata=metadata_with_context or None,
        conn=conn,
    )


def audit_event_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Return a JSON-safe audit event record."""

    metadata: Any = row["metadata"]
    if isinstance(metadata, str) and metadata:
        metadata = json.loads(metadata)
    return {
        "id": row["id"],
        "entity_type": row["entity_type"],
        "entity_id": row["entity_id"],
        "interface": row["interface"],
        "event_type": row["event_type"],
        "occurred_at": row["occurred_at"],
        "actor": row["actor"] if "actor" in row.keys() else "unknown",
        "name": row["name"],
        "ip_address": row["ip_address"],
        "public_key": row["public_key"],
        "metadata": metadata,
    }


def list_peer_audit_history(
    peer_ref: str,
    interface: str | None = None,
    *,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return audit events for a peer (full UUID or unique prefix)."""
    try:
        canonical_id = resolve_peer_ref(peer_ref, interface, active_only=False)
    except PeerNotFoundError:
        normalized = _normalize_peer_ref(peer_ref)
        if len(normalized) != _PEER_ID_HEX_LEN:
            matches = db.find_deleted_peer_id_from_audit(normalized)
            if not matches:
                raise PeerNotFoundError(
                    f"Peer {peer_ref} not found in current peers or audit history"
                )
            if len(matches) > 1:
                from wgpl.exceptions import AmbiguousPeerIdError

                raise AmbiguousPeerIdError(
                    f"Peer ID prefix '{peer_ref}' is ambiguous in audit history"
                )
            canonical_id = matches[0]
        else:
            canonical_id = str(uuid.UUID(hex=normalized))
    rows = db.list_audit_events(
        entity_type=db.AuditEntityType.PEER,
        entity_id=canonical_id,
        limit=limit,
        offset=offset,
    )
    return [audit_event_to_dict(row) for row in rows]


def list_interface_audit_history(
    ref: str,
    *,
    limit: int = 100,
    offset: int = 0,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return audit events for an interface (including after it was removed)."""
    try:
        iface_id = resolve_interface_ref(ref, conn=conn)
        rows = db.list_audit_events(
            entity_type=db.AuditEntityType.INTERFACE,
            entity_id=str(iface_id),
            limit=limit,
            offset=offset,
            conn=conn,
        )
    except InterfaceNotFoundError:
        # Fallback for deleted interfaces
        if ref.isdigit():
            rows = db.list_audit_events(
                entity_type=db.AuditEntityType.INTERFACE,
                entity_id=ref,
                limit=limit,
                offset=offset,
                conn=conn,
            )
        else:
            rows = db.list_audit_events(
                entity_type=db.AuditEntityType.INTERFACE,
                interface=ref,
                limit=limit,
                offset=offset,
                conn=conn,
            )
    return [audit_event_to_dict(row) for row in rows]


def get_effective_dns(peer_dns: str | None, iface_dns: str | None) -> str | None:
    """Return peer DNS override or interface default."""
    if peer_dns:
        return str(peer_dns)
    if iface_dns:
        return str(iface_dns)
    return None


def _normalize_peer_ref(ref: str) -> str:
    """Return lowercase hex ID without hyphens."""
    return ref.replace("-", "").lower()


def _format_peer_id_short(peer_id: str) -> str:
    """Return the 12-char hex prefix shown in peer list tables."""
    return _normalize_peer_ref(peer_id)[:12]


def resolve_peer_ref(
    ref: str,
    interface: str | None = None,
    *,
    active_only: bool = True,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Resolve a peer reference (full UUID or unique hex prefix) to canonical UUID."""
    normalized = _normalize_peer_ref(ref)

    if not normalized or not all(c in "0123456789abcdef" for c in normalized):
        raise PeerNotFoundError(f"Peer {ref} not found")

    iface_id = resolve_interface_ref(interface, conn=conn) if interface else None

    if len(normalized) == _PEER_ID_HEX_LEN:
        matches = db.find_peers_by_id_prefix(normalized, iface_id, conn=conn)
        if active_only:
            matches = [peer for peer in matches if _is_peer_active(peer)]
        exact = [
            peer for peer in matches if _normalize_peer_ref(peer["id"]) == normalized
        ]
        if len(exact) == 1:
            return str(exact[0]["id"])
        if len(exact) > 1:
            raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, exact))

    if len(normalized) < _MIN_PEER_ID_PREFIX_LEN:
        raise PeerNotFoundError(f"Peer {ref} not found")

    matches = db.find_peers_by_id_prefix(normalized, iface_id, conn=conn)
    if active_only:
        matches = [peer for peer in matches if _is_peer_active(peer)]
    if not matches:
        raise PeerNotFoundError(f"Peer {ref} not found")
    if len(matches) == 1:
        return str(matches[0]["id"])
    raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, matches))


def _ambiguous_interface_message(ref: str, matches: list[sqlite3.Row]) -> str:
    lines = [f"Multiple interfaces named '{ref}':"]
    for i, iface in enumerate(matches, 1):
        lines.append(
            f"  ID {iface['id']} → {iface['endpoint']}:{iface['port']} ({iface['address_pool']})"
        )
    lines.append(
        f"Specify the interface ID directly, e.g.: wgpl <command> {matches[0]['id']} ..."
    )
    return "\n".join(lines)


def resolve_interface_ref(
    ref: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Resolve an interface name or numerical ID to its unique integer ID."""
    if ref.isdigit():
        iface_id = int(ref)
        iface = db.get_interface(iface_id, conn=conn)
        if iface:
            return iface_id
        # Fallback to treating it as a name if no ID matches (unlikely, but robust)

    matches = db.get_interfaces_by_name(ref, conn=conn)
    if not matches:
        raise InterfaceNotFoundError(f"Interface {ref} not found")

    if len(matches) == 1:
        return int(matches[0]["id"])

    raise AmbiguousInterfaceError(_ambiguous_interface_message(ref, matches))


def get_interface_by_ref(ref: str) -> dict[str, Any]:
    """Resolve an interface name or ID and return its row as a dict."""
    iface_id = resolve_interface_ref(ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {ref} not found")
    return dict(iface)


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


def validate_allowed_ips(allowed_ips: str) -> str:
    """Validate AllowedIPs for client configuration export."""
    return wireformat.validate_allowed_ips(allowed_ips)


def validate_endpoint(endpoint: str) -> str:
    """Validate that endpoint is a valid IP address or FQDN."""
    endpoint = endpoint.strip()
    if not endpoint:
        raise ValueError("Endpoint cannot be empty")
    try:
        ipaddress.ip_address(endpoint)
        return endpoint
    except ValueError:
        pass

    # Regex for valid hostname (RFC 1123)
    hostname_re = re.compile(
        r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*"
        r"([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    )
    if not hostname_re.match(endpoint):
        raise ValueError(
            f"Invalid endpoint '{endpoint}'. Must be a valid IP or hostname."
        )
    return endpoint


def validate_public_key(key: str) -> str:
    """Validate that key is a valid 32-byte Base64 WireGuard public key."""
    key = key.strip()
    if not key:
        raise ValueError("Public key cannot be empty")
    try:
        decoded = base64.b64decode(key.encode("utf-8"), validate=True)
        if len(decoded) != 32:
            raise ValueError(
                f"Invalid public key length: expected 32 decoded bytes, got {len(decoded)}"
            )
    except Exception as exc:
        raise ValueError("Invalid public key: must be valid Base64") from exc
    return key


def validate_peer_name(name: str) -> str:
    """Validate and normalize peer names used in DB and CLI output."""
    normalized = name.strip()
    if not normalized:
        raise ValueError("Peer name cannot be empty")
    if len(normalized) > 64:
        raise ValueError("Peer name must be at most 64 characters")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$", normalized):
        raise ValueError(
            "Peer name contains invalid characters. Must start with alphanumeric and contain only alphanumerics, hyphens, and underscores."
        )
    return normalized


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


def _pool_used_ips(
    iface_id: int,
    conn: sqlite3.Connection,
    exclude_peer_id: str | None = None,
) -> tuple[ipaddress.IPv4Network, set[str]]:
    """Return the interface pool network and all reserved/used host IPs."""
    iface = db.get_interface(iface_id, conn=conn)
    if not iface:
        raise InterfaceNotFoundError(f"Interface ID {iface_id} not found")

    network = ipaddress.IPv4Network(iface["address_pool"], strict=False)
    used_ips = {
        peer["ip_address"]
        for peer in db.list_peers(iface_id, conn=conn)
        if _is_peer_active(peer)
    }

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


def _validate_requested_peer_ip(
    ip: str, network: ipaddress.IPv4Network, used_ips: set[str]
) -> None:
    """Raise if ip is invalid, outside the pool, reserved, or already used."""
    _validate_peer_ip_in_pool(ip, network)

    if ip in used_ips:
        raise IpAlreadyInUseError(f"IP {ip} is already assigned in this interface")


def _reclaim_inactive_peer_slots(
    iface_id: int,
    conn: sqlite3.Connection,
    *,
    ip: str | None = None,
    name: str | None = None,
    replaced_by_peer_id: str,
) -> None:
    """Soft-delete inactive peers blocking partial unique indexes; log reclaimed events."""
    if ip is None and name is None:
        return
    for peer in db.list_peers(iface_id, conn=conn):
        if _is_peer_active(peer) or peer["deleted_at"] is not None:
            continue
        blocks_ip = ip is not None and peer["ip_address"] == ip
        blocks_name = name is not None and peer["name"] == name
        if not blocks_ip and not blocks_name:
            continue
        slots: list[str] = []
        if blocks_ip:
            slots.append("ip")
        if blocks_name:
            slots.append("name")
        _audit_peer_from_row(
            peer,
            db.AuditEventType.RECLAIMED,
            conn,
            metadata={"replaced_by_peer_id": replaced_by_peer_id, "slot": slots},
        )
        db.remove_peer(peer["id"], conn=conn)


def allocate_peer_ip(
    iface_id: int,
    conn: sqlite3.Connection,
    requested: str | None = None,
    exclude_peer_id: str | None = None,
) -> str:
    """Allocate the next free IP or validate a requested IP within the interface pool."""
    network, used_ips = _pool_used_ips(iface_id, conn, exclude_peer_id=exclude_peer_id)

    if requested is None:
        if not used_ips:
            available = next((str(ip) for ip in network.hosts()), None)
            if available:
                return available
        else:
            try:
                used_ips_int = {int(ipaddress.IPv4Address(ip)) for ip in used_ips}
                max_ip_int = max(used_ips_int)

                # Check from max_ip + 1 to end of network
                for ip_int in range(max_ip_int + 1, int(network.broadcast_address)):
                    if ip_int not in used_ips_int:
                        return str(ipaddress.IPv4Address(ip_int))

                # Wrap around: Check from first host to max_ip
                for ip_int in range(int(network.network_address) + 1, max_ip_int):
                    if ip_int not in used_ips_int:
                        return str(ipaddress.IPv4Address(ip_int))
            except ValueError:
                pass
        raise NoAvailableIpsError(f"No available IPs in pool {network}")

    _validate_requested_peer_ip(requested, network, used_ips)
    return requested


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
    canonical_id = resolve_peer_ref(peer_id, interface_ref)
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


def assert_database_valid(interface: str | None = None) -> None:
    """Raise when the database fails consistency checks."""
    result = validate_state(interface)
    if result["status"] == "ok":
        return
    issues = cast(list[dict[str, str | None]], result["issues"])
    details = "; ".join(
        f"{issue.get('interface')}/{issue.get('peer')}: "
        f"{issue.get('code')} — {issue.get('detail')}"
        for issue in issues
    )
    raise WgplException(f"Database validation failed: {details}")


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


def validate_peers_in_pool(
    interface_name: str,
    pool_cidr: str,
    conn: sqlite3.Connection,
) -> None:
    """Raise PeersOutsidePoolError if any peer IP is invalid in the given pool."""
    network = ipaddress.IPv4Network(pool_cidr, strict=False)
    conflicts: list[dict[str, str]] = []

    iface_id = resolve_interface_ref(interface_name, conn=conn)

    for peer in db.list_peers(iface_id, conn=conn):
        if not _is_peer_active(peer):
            continue
        ip = str(peer["ip_address"])
        try:
            _validate_peer_ip_in_pool(ip, network)
        except InvalidPeerIpError as exc:
            conflicts.append(
                {"name": str(peer["name"]), "ip_address": ip, "detail": str(exc)}
            )

    if conflicts:
        raise PeersOutsidePoolError(interface_name, conflicts)


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
        canonical_id = resolve_peer_ref(
            peer_ref, str(iface_id), active_only=active_only, conn=conn
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


def validate_state(
    interface: str | None = None,
) -> dict[str, str | list[dict[str, str | None]]]:
    """Validate DB consistency without mutating state."""
    issues: list[dict[str, str | None]] = []

    if interface is not None:
        iface_id = resolve_interface_ref(interface)
        iface = db.get_interface(iface_id)
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
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": None,
                        "code": "invalid_dns",
                        "detail": f"Interface DNS: {exc}",
                    }
                )

        seen_ips: dict[str, str] = {}
        seen_names: dict[str, str] = {}
        for peer in db.list_peers(iface["id"]):
            if integrity.corrupt_expires_at(peer):
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": str(peer["name"]),
                        "code": "corrupt_expires_at",
                        "detail": f"Peer {peer['name']} has invalid expires_at",
                    }
                )
            if not _is_peer_active(peer):
                continue
            peer_name = str(peer["name"])
            ip = str(peer["ip_address"])
            if ip in seen_ips:
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": peer_name,
                        "code": "duplicate_ip",
                        "detail": f"IP {ip} also used by active peer {seen_ips[ip]}",
                    }
                )
            else:
                seen_ips[ip] = peer_name
            if peer_name in seen_names:
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": peer_name,
                        "code": "duplicate_name",
                        "detail": f"Name {peer_name} also used by peer {seen_names[peer_name]}",
                    }
                )
            else:
                seen_names[peer_name] = str(peer["id"])
            try:
                _validate_peer_ip_in_pool(ip, network)
            except InvalidPeerIpError as exc:
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": peer_name,
                        "code": "ip_outside_pool",
                        "detail": str(exc),
                    }
                )

            if peer["dns"]:
                try:
                    validate_dns(str(peer["dns"]))
                except InvalidDnsError as exc:
                    issues.append(
                        {
                            "interface": iface_name,
                            "peer": peer_name,
                            "code": "invalid_dns",
                            "detail": str(exc),
                        }
                    )

            try:
                integrity.validate_wire_peer_fields(peer)
            except WgplException as exc:
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": peer_name,
                        "code": "invalid_wire_fields",
                        "detail": str(exc),
                    }
                )

    status = "ok" if not issues else "error"
    return {"status": status, "issues": issues}


# --- Database Dump & Restore ---


def dump_database(target_path: str) -> None:
    """Creates a binary backup of the database to target_path."""
    with db.get_db() as conn:
        target_conn = sqlite3.connect(target_path)
        try:
            with target_conn:
                conn.backup(target_conn)
        finally:
            target_conn.close()
    os.chmod(target_path, 0o600)


def _cleanup_tmp_files(tmp_path: str) -> None:
    """Remove the tmp database and any WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        path = f"{tmp_path}{suffix}"
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _rotate_backups(db_path: str, keep: int = 3) -> None:
    """Keep only the newest ``keep`` backup files matching ``{db_path}.bak.*``."""
    backups = sorted(
        glob.glob(f"{db_path}.bak.*"),
        key=os.path.getmtime,
        reverse=True,
    )
    for old_backup in backups[keep:]:
        try:
            os.remove(old_backup)
        except OSError:
            pass


def _format_validation_issues(
    issues: list[dict[str, str | None]],
) -> str:
    return "; ".join(
        f"{issue.get('interface')}/{issue.get('peer')}: "
        f"{issue.get('code')} — {issue.get('detail')}"
        for issue in issues
    )


def _validate_restored_data() -> None:
    """Run consistency and full wire-format checks on WGPL_DB_PATH."""
    results = (
        validate_state(),
        integrity.validate_database(full=True),
    )
    issues: list[dict[str, str | None]] = []
    for result in results:
        if result["status"] != "ok":
            issues.extend(cast(list[dict[str, str | None]], result["issues"]))
    if issues:
        raise WgplException(
            f"Restored database failed validation: {_format_validation_issues(issues)}"
        )


def restore_database(source_path: str) -> list[str]:
    """Safely restores the database from a binary SQLite backup.

    Returns warning messages (e.g. WAL checkpoint). CLI prints them on stderr.

    Guarantees:
    - Original DB is not modified until the new one is fully validated.
    - Backup file (if created) has 0o600 permissions.
    - All temporary files are cleaned up on any failure path.
    - Restored schema is validated before replacing the live DB.
    - Old backups are rotated (keeps last 3).
    """
    warnings: list[str] = []
    db_path = db.get_db_path()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = f"{db_path}.bak.{timestamp}"
    tmp_path = f"{db_path}.tmp"

    # 1. Clean any leftover tmp files from a previous interrupted restore
    _cleanup_tmp_files(tmp_path)

    # 2. Create tmp db with secure permissions
    fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)

    # 3. Execute binary backup to tmp DB and validate schema
    try:
        tmp_conn = sqlite3.connect(tmp_path)
        try:
            source_conn = sqlite3.connect(source_path)
            try:
                with source_conn:
                    source_conn.backup(tmp_conn)
            finally:
                source_conn.close()
        finally:
            tmp_conn.close()
        db.assert_schema_contract(tmp_path)
    except WgplException:
        _cleanup_tmp_files(tmp_path)
        raise
    except Exception as e:
        _cleanup_tmp_files(tmp_path)
        raise WgplException(f"Failed to restore database from backup: {e}") from e

    saved_db_path = os.environ.get("WGPL_DB_PATH")
    try:
        os.environ["WGPL_DB_PATH"] = tmp_path
        try:
            _validate_restored_data()
            db.init_db()
        except BaseException:
            _cleanup_tmp_files(tmp_path)
            raise
    finally:
        if saved_db_path is None:
            os.environ.pop("WGPL_DB_PATH", None)
        else:
            os.environ["WGPL_DB_PATH"] = saved_db_path

    # 4. Backup current db with WAL checkpoint for consistency
    try:
        if os.path.exists(db_path):
            checkpoint_conn = sqlite3.connect(db_path)
            try:
                result = checkpoint_conn.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                if result and result[0] != 0:
                    warnings.append(
                        "Warning: WAL checkpoint was blocked. "
                        "Backup may not include uncommitted WAL data."
                    )
            finally:
                checkpoint_conn.close()

            shutil.copy2(db_path, backup_path)
            os.chmod(backup_path, 0o600)
            _rotate_backups(db_path, keep=3)
    except Exception:
        _cleanup_tmp_files(tmp_path)
        raise

    # 5. Atomic replacement and final hardening
    try:
        for suffix in ("-wal", "-shm"):
            for path_base in (db_path, tmp_path):
                sidecar = f"{path_base}{suffix}"
                if os.path.exists(sidecar):
                    try:
                        os.remove(sidecar)
                    except OSError:
                        pass

        os.rename(tmp_path, db_path)
        os.chmod(db_path, 0o600)
    except Exception:
        _cleanup_tmp_files(tmp_path)
        raise

    return warnings
