import ipaddress
import uuid
import datetime
import qrcode
import io
import sqlite3
import re
from collections.abc import Mapping, Sequence
from typing import Any

from . import db
from .db import UNSET, UnsetType
from . import integrity
from . import routing
from .routing import AllowedIpsPolicy, PeerRole
from . import wireformat
from . import wireguard
from .audit import (
    _audit_interface_event,
    _audit_node_event,
    _audit_peer_from_row,
    audit_event_to_dict,
    list_interface_audit_history,
    list_node_audit_history,
    list_peer_audit_history,
)
from .ipam import _reclaim_inactive_peer_slots, allocate_peer_ip
from .refs import (
    PeerAccess,
    get_interface_by_ref,
    resolve_interface_ref,
    resolve_node_ref,
    resolve_peer_ref,
)
from .restore import dump_database, restore_database
from .consistency import assert_database_valid, validate_state
from .fields import (
    effective_dns,
    effective_peer_dns,
    effective_peer_keepalive,
    effective_peer_mtu,
)
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
    NodeHasPeersError,
    NodeNotFoundError,
    NoUpdateFieldsError,
    PeerAlreadyExistsError,
    PeerInterfaceMismatchError,
    PeerNotFoundError,
    WgplException,
)


def _validate_mtu_keepalive(mtu: int | None, keepalive: int | None) -> None:
    """Reject mtu/keepalive values outside wire-safe ranges at mutation time."""
    try:
        if mtu is not None:
            integrity.validate_wire_mtu(mtu)
        if keepalive is not None:
            integrity.validate_wire_keepalive(keepalive)
    except WgplException as exc:
        raise ValueError(str(exc)) from exc


def _validate_role(role: str) -> str:
    if role not in {PeerRole.ENDPOINT, PeerRole.SUBNET_ROUTER}:
        raise ValueError(
            f"Invalid role '{role}'. Must be '{PeerRole.ENDPOINT}' or "
            f"'{PeerRole.SUBNET_ROUTER}'."
        )
    return role


def _validate_allowed_ips_policy(policy: str) -> str:
    valid = {item.value for item in AllowedIpsPolicy}
    if policy not in valid:
        raise ValueError(
            f"Invalid allowed_ips_policy '{policy}'. Must be one of: "
            f"{', '.join(sorted(valid))}."
        )
    return policy


def _normalize_routed_networks(value: str, *, address_pool: str) -> str:
    normalized = routing.normalize_cidr_list(value)
    integrity.validate_routed_networks_list(
        normalized,
        field="routed_networks",
        address_pool=address_pool,
        tunnel_ip=None,
    )
    return normalized


def _normalize_custom_allowed_ips(value: str) -> str:
    return routing.normalize_cidr_list(value)


def _resolve_peer_routing_for_write(
    *,
    role: str,
    routed_networks: str | None,
    allowed_ips_policy: str,
    custom_allowed_ips: str | None,
    address_pool: str,
) -> tuple[str, str | None, str, str | None]:
    """Validate and normalize routing fields for peer create/update."""
    validated_role = _validate_role(role)
    validated_policy = _validate_allowed_ips_policy(allowed_ips_policy)

    normalized_routed: str | None = None
    if routed_networks is not None:
        normalized_routed = _normalize_routed_networks(
            routed_networks, address_pool=address_pool
        )

    if validated_role == PeerRole.ENDPOINT:
        if normalized_routed is not None:
            raise ValueError("endpoint peers must not have routed_networks")
    elif normalized_routed is None:
        raise ValueError("subnet_router requires routed_networks")

    normalized_custom: str | None = None
    if validated_policy == AllowedIpsPolicy.CUSTOM:
        if custom_allowed_ips is None:
            raise ValueError(
                "custom_allowed_ips is required when allowed_ips_policy is custom"
            )
        normalized_custom = _normalize_custom_allowed_ips(custom_allowed_ips)
    elif custom_allowed_ips is not None:
        raise ValueError(
            "custom_allowed_ips is only valid when allowed_ips_policy is custom"
        )

    return validated_role, normalized_routed, validated_policy, normalized_custom


__all__ = [
    "AllowedIpsPolicy",
    "PeerAccess",
    "PeerRole",
    "add_interface",
    "add_node",
    "add_peer",
    "allocate_peer_ip",
    "assert_database_valid",
    "audit_event_to_dict",
    "diagnose_database",
    "dump_database",
    "ensure_database",
    "get_effective_dns",
    "get_interface_by_ref",
    "get_interface_config",
    "get_node_by_ref",
    "explain_peer_routing",
    "get_peer_config",
    "get_peer_config_payload",
    "get_peer_qr",
    "get_peer_qr_png_bytes",
    "get_peer_status",
    "interface_dns_map",
    "list_interface_audit_history",
    "list_interfaces",
    "list_node_audit_history",
    "list_nodes",
    "list_peer_audit_history",
    "list_peers",
    "peer_row_to_public_dict",
    "peer_rows_to_public_dicts",
    "prune_nodes",
    "prune_peers",
    "remove_interface",
    "remove_node",
    "remove_peer",
    "repair_database",
    "resolve_interface_ref",
    "resolve_node_ref",
    "resolve_peer_ref",
    "restore_database",
    "sync_interface",
    "update_interface",
    "update_node",
    "update_peer",
    "validate_allowed_ips",
    "validate_dns",
    "validate_endpoint",
    "validate_peer_name",
    "validate_public_key",
    "validate_state",
]


def get_peer_status(peer: sqlite3.Row | Mapping[str, object]) -> str:
    """Return lifecycle label: Active, Expired, or Deleted."""
    if integrity.is_peer_deleted(peer):
        return "Deleted"
    if not integrity.is_peer_active(peer):
        return "Expired"
    return "Active"


def _peer_optional_field(peer: sqlite3.Row | Mapping[str, object], field: str) -> Any:
    if isinstance(peer, sqlite3.Row):
        return peer[field] if field in peer.keys() else None
    if field in peer.keys():
        return peer[field]
    return None


def _optional_int_field(
    row: sqlite3.Row | Mapping[str, object], field: str
) -> int | None:
    raw = _peer_optional_field(row, field)
    if raw is None:
        return None
    return int(raw)


def peer_row_to_public_dict(
    peer: sqlite3.Row | Mapping[str, object],
    iface_dns: dict[int, str | None] | None = None,
    iface: sqlite3.Row | Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Return a JSON-safe peer record without private_key or preshared_key.

    Includes ``desc``, effective/override ``mtu`` and ``keepalive`` (same model
    as ``update_peer`` return values) for list/show JSON parity with human UI.
    Includes ``interface`` (hub name) alongside ``interface_id`` when the
    interface row is available.
    """
    iface_dns_map = iface_dns or {}
    interface_id = int(str(peer["interface_id"]))
    peer_dns = _peer_optional_field(peer, "dns")
    if peer_dns is not None:
        peer_dns = str(peer_dns)
    created_at = peer["created_at"]
    desc = _peer_optional_field(peer, "desc")
    if desc is not None:
        desc = str(desc)
    mtu_override = _optional_int_field(peer, "mtu")
    keepalive_override = _optional_int_field(peer, "keepalive")
    iface_mtu = _optional_int_field(iface, "mtu") if iface is not None else None
    iface_keepalive = (
        _optional_int_field(iface, "keepalive") if iface is not None else None
    )
    iface_name = _peer_optional_field(iface, "name") if iface is not None else None
    if iface_name is not None:
        iface_name = str(iface_name)
    return {
        "id": str(peer["id"]),
        "interface_id": str(interface_id),
        "interface": iface_name,
        "node_id": (
            str(_peer_optional_field(peer, "node_id"))
            if _peer_optional_field(peer, "node_id") is not None
            else None
        ),
        "name": str(peer["name"]),
        "node": str(peer["name"]),
        "ip_address": str(peer["ip_address"]),
        "public_key": str(peer["public_key"]),
        "created_at": str(created_at) if created_at is not None else None,
        "dns": get_effective_dns(peer_dns, iface_dns_map.get(interface_id)),
        "dns_override": peer_dns,
        "desc": desc,
        "mtu": mtu_override if mtu_override is not None else iface_mtu,
        "mtu_override": mtu_override,
        "keepalive": (
            keepalive_override if keepalive_override is not None else iface_keepalive
        ),
        "keepalive_override": keepalive_override,
        "status": get_peer_status(peer),
        "expires_at": _peer_optional_field(peer, "expires_at"),
        "deleted_at": _peer_optional_field(peer, "deleted_at"),
        "role": str(_peer_optional_field(peer, "role") or PeerRole.ENDPOINT),
        "routed_networks": _peer_optional_field(peer, "routed_networks"),
        "allowed_ips_policy": str(
            _peer_optional_field(peer, "allowed_ips_policy")
            or AllowedIpsPolicy.VPN_ONLY
        ),
        "custom_allowed_ips": _peer_optional_field(peer, "custom_allowed_ips"),
    }


def _active_peers_on_interface(
    interface_id: int,
) -> list[sqlite3.Row]:
    """Return all active peers on an interface (for routing derivation)."""
    return [row for row in db.list_peers(interface_id) if integrity.is_peer_active(row)]


def _derived_allowed_ips_for_peer(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    active_peers: Sequence[sqlite3.Row | Mapping[str, object]],
) -> tuple[list[str], list[str]]:
    """Return (hub_allowed_ips, client_allowed_ips) for an active peer."""
    hub_ips = routing.resolve_hub_allowed_ips(peer)
    client_ips = routing.resolve_client_allowed_ips(peer, iface, active_peers)
    return hub_ips, client_ips


def _interface_routing_context(
    interface_id: int,
) -> tuple[sqlite3.Row | None, list[sqlite3.Row]]:
    """Return interface row and active peers for routing; empty when DB unavailable."""
    try:
        iface = db.get_interface(interface_id)
    except WgplException:
        return None, []
    if iface is None:
        return None, []
    return iface, _active_peers_on_interface(interface_id)


def peer_rows_to_public_dicts(
    peers: Sequence[sqlite3.Row | Mapping[str, object]],
    iface_dns: dict[int, str | None] | None = None,
) -> list[dict[str, Any]]:
    """Convert peer rows to JSON-safe dicts including derived AllowedIPs."""
    iface_dns_map = iface_dns or {}
    iface_cache: dict[int, tuple[sqlite3.Row | None, list[sqlite3.Row]]] = {}
    result: list[dict[str, Any]] = []

    for peer in peers:
        iface_id = int(str(peer["interface_id"]))
        if iface_id not in iface_cache:
            iface_cache[iface_id] = _interface_routing_context(iface_id)

        iface, active_peers = iface_cache[iface_id]
        record = peer_row_to_public_dict(peer, iface_dns_map, iface=iface)
        if iface is not None and integrity.is_peer_active(peer):
            hub_ips, client_ips = _derived_allowed_ips_for_peer(
                peer, iface, active_peers
            )
            record["hub_allowed_ips"] = hub_ips
            record["client_allowed_ips"] = client_ips
        else:
            record["hub_allowed_ips"] = []
            record["client_allowed_ips"] = []
        result.append(record)

    return result


def get_effective_dns(peer_dns: str | None, iface_dns: str | None) -> str | None:
    """Return peer DNS override or interface default."""
    return effective_dns(peer_dns, iface_dns)


def _peer_actual_changed_fields(
    before: sqlite3.Row,
    after: sqlite3.Row,
    candidates: list[str],
) -> dict[str, dict[str, Any]]:
    """Return candidate field names and their state diffs."""
    column_map = {
        "ip_address": "ip_address",
        "dns": "dns",
        "desc": "desc",
        "mtu": "mtu",
        "keepalive": "keepalive",
        "expires": "expires_at",
        "role": "role",
        "routed_networks": "routed_networks",
        "allowed_ips_policy": "allowed_ips_policy",
        "custom_allowed_ips": "custom_allowed_ips",
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
        "routed_networks": "routed_networks",
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
    routed_networks: str | None = None,
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
    _validate_mtu_keepalive(mtu, keepalive)
    normalized_routed: str | None = None
    if routed_networks is not None:
        normalized_routed = _normalize_routed_networks(
            routed_networks, address_pool=normalized_pool
        )

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
            routed_networks=normalized_routed,
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
    if normalized_routed is not None:
        result["routed_networks"] = normalized_routed
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


# --- Nodes (global device identities) ---


def _validate_node_desc(desc: str | None) -> None:
    if desc is not None:
        integrity.validate_wire_safe_text(desc, "desc")


def add_node(name: str, desc: str | None = None) -> dict[str, Any]:
    """Create a global node (device identity)."""
    name = validate_peer_name(name)
    _validate_node_desc(desc)
    node_id = str(uuid.uuid4())
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with db.transaction() as conn:
        db.add_node(node_id, name, created_at, desc=desc, conn=conn)
        _audit_node_event(
            node_id,
            name,
            db.AuditEventType.CREATED,
            conn,
            metadata={"desc": desc} if desc else None,
        )
    return {"id": node_id, "name": name, "desc": desc, "created_at": created_at}


def _count_active_peers_for_node(
    node_id: str,
    conn: sqlite3.Connection,
) -> int:
    """Count peers attached to a node that are active (not soft-deleted or expired)."""
    return sum(
        1
        for peer in db.list_peers(conn=conn)
        if peer["node_id"] is not None
        and str(peer["node_id"]) == node_id
        and integrity.is_peer_active(peer)
    )


def list_nodes() -> list[dict[str, Any]]:
    """Return all nodes as plain dicts, including their attachment count."""
    with db.transaction(verify=True) as conn:
        nodes = db.list_nodes(conn=conn)
        return [
            {
                **dict(row),
                "attachment_count": _count_active_peers_for_node(str(row["id"]), conn),
            }
            for row in nodes
        ]


def get_node_by_ref(ref: str) -> dict[str, Any]:
    """Resolve a node reference and return its row as a dict (with attachment count)."""
    with db.transaction(verify=True) as conn:
        node_id = resolve_node_ref(ref, conn=conn)
        node = db.get_node(node_id, conn=conn)
        if not node:
            raise NodeNotFoundError(f"Node {ref} not found")
        count = _count_active_peers_for_node(node_id, conn=conn)
    result = dict(node)
    result["attachment_count"] = count
    return result


def update_node(
    ref: str,
    *,
    name: str | None = None,
    desc: str | None = None,
    clear_desc: bool = False,
) -> dict[str, Any]:
    """Update a node's identity fields (name/desc)."""
    if clear_desc and desc is not None:
        raise ValueError("Cannot set both desc and clear_desc")
    if name is None and desc is None and not clear_desc:
        raise NoUpdateFieldsError("No fields provided to update")
    if name is not None:
        name = validate_peer_name(name)
    normalized_desc: str | None | UnsetType = UNSET
    if clear_desc:
        normalized_desc = None
    elif desc is not None:
        _validate_node_desc(desc)
        normalized_desc = desc

    with db.transaction() as conn:
        node_id = resolve_node_ref(ref, conn=conn)
        before = db.get_node(node_id, conn=conn)
        if not before:
            raise NodeNotFoundError(f"Node {ref} not found")
        db.update_node(
            node_id,
            name=name if name is not None else UNSET,
            desc=normalized_desc,
            conn=conn,
        )
        after = db.get_node(node_id, conn=conn)
        if not after:
            raise NodeNotFoundError(f"Node {ref} not found after update")
        changed: dict[str, dict[str, Any]] = {}
        if name is not None and before["name"] != after["name"]:
            changed["name"] = {"old": before["name"], "new": after["name"]}
        if (clear_desc or desc is not None) and before["desc"] != after["desc"]:
            changed["desc"] = {"old": before["desc"], "new": after["desc"]}
        if changed:
            _audit_node_event(
                node_id,
                str(after["name"]),
                db.AuditEventType.UPDATED,
                conn,
                metadata={"fields": changed},
            )
    return dict(after)


def remove_node(ref: str, *, force: bool = False) -> None:
    """Remove a node and (with --force) cascade its attachments."""
    with db.transaction() as conn:
        node_id = resolve_node_ref(ref, conn=conn)
        node = db.get_node(node_id, conn=conn)
        if not node:
            raise NodeNotFoundError(f"Node {ref} not found")
        name = str(node["name"])
        active_count = _count_active_peers_for_node(node_id, conn=conn)
        if active_count > 0 and not force:
            raise NodeHasPeersError(
                f"Node {name} has {active_count} active attachment(s). "
                "Remove those peers first, or use --force."
            )
        attachments = [
            peer for peer in db.list_peers(conn=conn) if str(peer["node_id"]) == node_id
        ]
        for peer in attachments:
            _audit_peer_from_row(
                peer,
                db.AuditEventType.CASCADE_REMOVED,
                conn,
                metadata={"trigger": "node_removed", "node": name},
            )
        _audit_node_event(
            node_id,
            name,
            db.AuditEventType.REMOVED,
            conn,
            metadata={
                "attachment_count": len(attachments),
                "forced": bool(active_count and force),
            },
        )
        db.remove_node(node_id, conn=conn)


def prune_nodes() -> int:
    """Physically remove nodes with no attachments (any lifecycle state)."""
    removed = 0
    with db.transaction() as conn:
        for node in db.list_nodes(conn=conn):
            node_id = str(node["id"])
            total = db.count_peers_for_node(node_id, conn=conn, include_deleted=True)
            if total == 0:
                _audit_node_event(
                    node_id,
                    str(node["name"]),
                    db.AuditEventType.PRUNED,
                    conn,
                    metadata={"reason": "orphan"},
                )
                db.remove_node(node_id, conn=conn)
                removed += 1
    return removed


def ensure_database() -> None:
    """Initialize the database connection and schema."""
    db.init_db()


def diagnose_database() -> list[dict[str, str | None]]:
    """Return structural and consistency issues for the live database."""
    return db.diagnose_database()


def repair_database() -> list[str]:
    """Apply documented database repairs (triggers, deleted_at normalization)."""
    return db.repair_database()


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
    return effective_peer_dns(peer, iface)


def _effective_peer_mtu(peer: sqlite3.Row, iface: sqlite3.Row) -> int | None:
    return effective_peer_mtu(peer, iface)


def _effective_peer_keepalive(peer: sqlite3.Row, iface: sqlite3.Row) -> int | None:
    return effective_peer_keepalive(peer, iface)


def _resolve_node_for_attachment(
    conn: sqlite3.Connection,
    *,
    name: str | None,
    node_ref: str | None,
    created_at: str,
) -> tuple[str, str, bool]:
    """Resolve the node to attach: strict via node_ref, or find-or-create via name.

    Returns (node_id, node_name, node_created).
    """
    if (name is None) == (node_ref is None):
        raise ValueError(
            "Provide exactly one of a peer name (positional) or --node <ref>."
        )

    if node_ref is not None:
        node_id = resolve_node_ref(node_ref, conn=conn)
        node = db.get_node(node_id, conn=conn)
        if not node:
            raise NodeNotFoundError(f"Node {node_ref} not found")
        return node_id, str(node["name"]), False

    node_name = validate_peer_name(str(name))
    existing = db.get_node_by_name(node_name, conn=conn)
    if existing is not None:
        return str(existing["id"]), node_name, False

    node_id = str(uuid.uuid4())
    db.add_node(node_id, node_name, created_at, desc=None, conn=conn)
    _audit_node_event(
        node_id,
        node_name,
        db.AuditEventType.CREATED,
        conn,
        metadata={"via": "peer_add"},
    )
    return node_id, node_name, True


def add_peer(
    interface_name: str,
    name: str | None = None,
    ip_address: str | None = None,
    dns: str | None = None,
    expires: str | None = None,
    desc: str | None = None,
    mtu: int | None = None,
    keepalive: int | None = None,
    role: str = PeerRole.ENDPOINT,
    routed_networks: str | None = None,
    allowed_ips_policy: str = AllowedIpsPolicy.VPN_ONLY,
    custom_allowed_ips: str | None = None,
    *,
    node_ref: str | None = None,
) -> dict[str, Any]:
    """Attach a node to an interface as a peer, allocating an IP and keys.

    Provide either ``name`` (positional; find-or-create the node) or ``node_ref``
    (strict; attach an existing node). Returns the peer's essential information.
    """
    normalized_dns = validate_dns(dns) if dns is not None else None
    _validate_mtu_keepalive(mtu, keepalive)

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_name, conn=conn)

        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        node_id, node_name, node_created = _resolve_node_for_attachment(
            conn, name=name, node_ref=node_ref, created_at=created_at
        )

        allocated_ip = allocate_peer_ip(iface_id, conn, ip_address)

        keypair = wireguard.generate_keypair()
        preshared_key = wireguard.generate_preshared_key()

        peer_id = str(uuid.uuid4())
        _reclaim_inactive_peer_slots(
            iface_id,
            conn,
            ip=allocated_ip,
            node_id=node_id,
            replaced_by_peer_id=peer_id,
        )

        expires_at = None
        if expires:
            expires_at = integrity.parse_future_duration(expires).isoformat()

        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface ID {iface_id} not found")

        validated_role, normalized_routed, validated_policy, normalized_custom = (
            _resolve_peer_routing_for_write(
                role=role,
                routed_networks=routed_networks,
                allowed_ips_policy=allowed_ips_policy,
                custom_allowed_ips=custom_allowed_ips,
                address_pool=str(iface["address_pool"]),
            )
        )

        prospective_peer: dict[str, object] = {
            "id": peer_id,
            "interface_id": iface_id,
            "node_id": node_id,
            "name": node_name,
            "ip_address": allocated_ip,
            "public_key": keypair.public_key,
            "preshared_key": preshared_key,
            "deleted_at": None,
            "expires_at": expires_at,
            "role": validated_role,
            "routed_networks": normalized_routed,
            "allowed_ips_policy": validated_policy,
            "custom_allowed_ips": normalized_custom,
        }
        integrity.assert_peer_activation(
            prospective_peer, iface, conn=conn, exclude_peer_id=peer_id
        )

        db.add_peer(
            id=peer_id,
            interface_id=iface_id,
            node_id=node_id,
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
            role=validated_role,
            routed_networks=normalized_routed,
            allowed_ips_policy=validated_policy,
            custom_allowed_ips=normalized_custom,
            conn=conn,
        )

        created_peer = db.get_peer(peer_id, conn=conn)
        if created_peer:
            meta: dict[str, Any] = {
                "has_psk": bool(preshared_key),
                "node_created": node_created,
            }
            if expires_at:
                meta["expires_at"] = expires_at
            _audit_peer_from_row(
                created_peer,
                db.AuditEventType.CREATED,
                conn,
                metadata=meta,
            )

    effective_dns = normalized_dns or (str(iface["dns"]) if iface["dns"] else None)

    return {
        "id": peer_id,
        "name": node_name,
        "node": node_name,
        "node_id": node_id,
        "node_created": node_created,
        "ip_address": allocated_ip,
        "public_key": keypair.public_key,
        "dns": effective_dns,
        "desc": desc,
        "mtu": mtu,
        "keepalive": keepalive,
        "role": validated_role,
        "routed_networks": normalized_routed,
        "allowed_ips_policy": validated_policy,
        "custom_allowed_ips": normalized_custom,
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
            if not integrity.is_peer_active(peer)
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


def _emit_server_config(interface_ref: str) -> str:
    """Emit server syncconf after consistency preflight and export validation."""
    assert_database_valid(interface_ref)
    iface_id = resolve_interface_ref(interface_ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_ref} not found")

    integrity.assert_exportable_interface(iface)
    peers = db.list_peers(iface_id)
    peer_exports: list[tuple[sqlite3.Row | Mapping[str, object], list[str]]] = []
    for peer in peers:
        if not integrity.is_peer_active(peer):
            continue
        integrity.assert_exportable_peer(peer, iface, mode="server")
        hub_ips = routing.resolve_hub_allowed_ips(peer)
        peer_exports.append((peer, hub_ips))

    return wireformat.build_server_config(iface, peer_exports)


def _emit_client_config(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> str:
    """Emit client config after resolve, preflight, and export validation."""
    canonical_id = resolve_peer_ref(
        peer_id, interface_ref, access=PeerAccess.EXPORT_SECRET
    )
    peer = db.get_peer(canonical_id)
    if not peer:
        raise PeerNotFoundError(f"Peer {peer_id} not found")
    if not integrity.is_peer_active(peer):
        raise PeerNotFoundError(f"Peer {peer_id} not found")

    iface = db.get_interface(peer["interface_id"])
    if not iface:
        raise InterfaceNotFoundError(f"Interface ID {peer['interface_id']} not found")

    iface_ref = interface_ref if interface_ref is not None else str(iface["id"])
    assert_database_valid(iface_ref)

    peer = db.get_peer(canonical_id)
    if not peer or not integrity.is_peer_active(peer):
        raise PeerNotFoundError(f"Peer {peer_id} not found")

    integrity.assert_exportable_interface(iface)
    integrity.assert_exportable_peer(peer, iface, mode="client")
    if allowed_ips is None:
        active_peers = [
            row
            for row in db.list_peers(int(str(peer["interface_id"])))
            if integrity.is_peer_active(row)
        ]
        resolved = routing.resolve_client_allowed_ips(peer, iface, active_peers)
        allowed_ips = ",".join(resolved)
    return wireformat.build_client_config(peer, iface, allowed_ips)


def get_peer_config(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> str:
    """Generates the WireGuard client configuration file (.conf format) in plain text."""
    return _emit_client_config(peer_id, allowed_ips, interface_ref=interface_ref)


def get_peer_config_payload(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> dict[str, Any]:
    """Return client config text plus derived AllowedIPs metadata for JSON output."""
    config = get_peer_config(
        peer_id, allowed_ips=allowed_ips, interface_ref=interface_ref
    )
    canonical_id = resolve_peer_ref(
        peer_id, interface_ref, access=PeerAccess.EXPORT_SECRET
    )
    peer = db.get_peer(canonical_id)
    if not peer or not integrity.is_peer_active(peer):
        raise PeerNotFoundError(f"Peer {peer_id} not found")

    iface = db.get_interface(peer["interface_id"])
    if not iface:
        raise InterfaceNotFoundError(f"Interface ID {peer['interface_id']} not found")

    if allowed_ips is None:
        active_peers = _active_peers_on_interface(int(str(peer["interface_id"])))
        client_ips = routing.resolve_client_allowed_ips(peer, iface, active_peers)
        source = "derived"
    else:
        client_ips = [part.strip() for part in allowed_ips.split(",") if part.strip()]
        source = "override"

    return {
        "config": config,
        "client_allowed_ips": client_ips,
        "allowed_ips_source": source,
    }


def explain_peer_routing(
    peer_id: str,
    *,
    interface_ref: str | None = None,
) -> dict[str, Any]:
    """Explain derived hub/client AllowedIPs and LAN↔LAN four-leg checklist."""
    canonical_id = resolve_peer_ref(peer_id, interface_ref, access=PeerAccess.MUTATE)
    peer = db.get_peer(canonical_id)
    if not peer:
        raise PeerNotFoundError(f"Peer {peer_id} not found")

    iface = db.get_interface(peer["interface_id"])
    if not iface:
        raise InterfaceNotFoundError(f"Interface ID {peer['interface_id']} not found")

    iface_dns = interface_dns_map()
    public = peer_rows_to_public_dicts([peer], iface_dns)[0]
    role = str(_peer_optional_field(peer, "role") or PeerRole.ENDPOINT)
    policy = str(
        _peer_optional_field(peer, "allowed_ips_policy") or AllowedIpsPolicy.VPN_ONLY
    )

    hub_ips: list[str] = list(public["hub_allowed_ips"])
    client_ips: list[str] = list(public["client_allowed_ips"])
    checklist: list[dict[str, Any]] = []

    if integrity.is_peer_active(peer) and role == PeerRole.SUBNET_ROUTER:
        local_lans = routing.parse_cidr_list(
            str(_peer_optional_field(peer, "routed_networks") or "")
        )
        active_peers = _active_peers_on_interface(int(str(peer["interface_id"])))
        other_routers = [
            row
            for row in active_peers
            if str(_peer_optional_field(row, "role") or PeerRole.ENDPOINT)
            == PeerRole.SUBNET_ROUTER
            and str(row["id"]) != str(peer["id"])
        ]

        for other in other_routers:
            other_hub = routing.resolve_hub_allowed_ips(other)
            other_client = routing.resolve_client_allowed_ips(
                other, iface, active_peers
            )
            other_lans = routing.parse_cidr_list(
                str(_peer_optional_field(other, "routed_networks") or "")
            )
            local_hub_ok = all(str(net) in hub_ips for net in local_lans)
            remote_hub_ok = all(str(net) in other_hub for net in other_lans)
            local_client_ok = all(str(net) in client_ips for net in other_lans)
            remote_client_ok = all(str(net) in other_client for net in local_lans)
            checklist.append(
                {
                    "remote_peer": str(other["name"]),
                    "hub_local_routes_local_lan": local_hub_ok,
                    "hub_remote_routes_remote_lan": remote_hub_ok,
                    "local_client_routes_remote_lan": local_client_ok,
                    "remote_client_routes_local_lan": remote_client_ok,
                    "complete": (
                        local_hub_ok
                        and remote_hub_ok
                        and local_client_ok
                        and remote_client_ok
                    ),
                }
            )

    return {
        "peer": public,
        "role": role,
        "allowed_ips_policy": policy,
        "hub_allowed_ips": hub_ips,
        "client_allowed_ips": client_ips,
        "interface_routed_networks": _peer_optional_field(iface, "routed_networks"),
        "peer_routed_networks": _peer_optional_field(peer, "routed_networks"),
        "lan_to_lan_checklist": checklist,
    }


def get_peer_qr(
    peer_id: str,
    allowed_ips: str | None = None,
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
    allowed_ips: str | None = None,
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
    return _emit_server_config(interface_ref)


def sync_interface(interface_ref: str) -> None:
    """Syncs the WireGuard interface with the DB state declaratively using syncconf."""
    iface_id = resolve_interface_ref(interface_ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {interface_ref} not found")
    name = str(iface["name"])
    conf_content = _emit_server_config(interface_ref)
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
        "routed_networks": iface["routed_networks"]
        if "routed_networks" in iface.keys()
        else None,
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
    routed_networks: str | None = None,
    clear_routed_networks: bool = False,
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
    if clear_routed_networks and routed_networks is not None:
        raise ValueError("Cannot set both routed_networks and clear_routed_networks")

    has_field = any(
        v is not None
        for v in (
            endpoint,
            port,
            public_key,
            address_pool,
            dns,
            desc,
            mtu,
            keepalive,
            routed_networks,
        )
    )
    if (
        not has_field
        and not clear_dns
        and not clear_desc
        and not clear_mtu
        and not clear_keepalive
        and not clear_routed_networks
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
        or routed_networks is not None
        or clear_routed_networks
    ):
        if "re_export_clients" not in hints:
            hints.append("re_export_clients")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    _validate_mtu_keepalive(mtu, keepalive)

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

    normalized_routed: str | None | UnsetType = UNSET
    if clear_routed_networks:
        normalized_routed = None

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
    if routed_networks is not None or clear_routed_networks:
        changed_fields.append("routed_networks")

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(ref, conn=conn)
        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {ref} not found")

        if routed_networks is not None:
            pool_for_routes = normalized_pool or str(iface["address_pool"])
            normalized_routed = _normalize_routed_networks(
                routed_networks, address_pool=pool_for_routes
            )

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
            routed_networks=normalized_routed,
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
    role: str | None = None,
    routed_networks: str | None = None,
    clear_routed_networks: bool = False,
    allowed_ips_policy: str | None = None,
    custom_allowed_ips: str | None = None,
    clear_custom_allowed_ips: bool = False,
) -> dict[str, Any]:
    """Update peer fields. Returns safe peer data and operational hints."""
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
    if clear_routed_networks and routed_networks is not None:
        raise ValueError("Cannot set both routed_networks and clear_routed_networks")
    if clear_custom_allowed_ips and custom_allowed_ips is not None:
        raise ValueError(
            "Cannot set both custom_allowed_ips and clear_custom_allowed_ips"
        )

    has_field = any(
        v is not None
        for v in (
            ip_address,
            dns,
            desc,
            mtu,
            keepalive,
            expires,
            role,
            routed_networks,
            allowed_ips_policy,
            custom_allowed_ips,
        )
    )
    if (
        not has_field
        and not clear_dns
        and not clear_desc
        and not clear_mtu
        and not clear_keepalive
        and not clear_expires
        and not clear_routed_networks
        and not clear_custom_allowed_ips
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
        or role is not None
        or routed_networks is not None
        or clear_routed_networks
        or allowed_ips_policy is not None
        or custom_allowed_ips is not None
        or clear_custom_allowed_ips
    ):
        hints.append("re_export_client")
    if (
        role is not None
        or routed_networks is not None
        or clear_routed_networks
        or ip_address is not None
    ):
        hints.append("apply_server")

    _validate_mtu_keepalive(mtu, keepalive)

    normalized_dns = _resolve_optional(validate_dns(dns) if dns else None, clear_dns)
    normalized_desc = _resolve_optional(desc, clear_desc)
    normalized_mtu = _resolve_optional(mtu, clear_mtu)
    normalized_keepalive = _resolve_optional(keepalive, clear_keepalive)

    normalized_expires = _resolve_optional(
        integrity.parse_future_duration(expires).isoformat() if expires else None,
        clear_expires,
    )

    changed_fields: list[str] = []
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
    if role is not None:
        changed_fields.append("role")
    if routed_networks is not None or clear_routed_networks:
        changed_fields.append("routed_networks")
    if allowed_ips_policy is not None:
        changed_fields.append("allowed_ips_policy")
    if custom_allowed_ips is not None or clear_custom_allowed_ips:
        changed_fields.append("custom_allowed_ips")

    with db.transaction() as conn:
        iface_id = resolve_interface_ref(interface_ref, conn=conn)
        resolve_access = (
            PeerAccess.MUTATE if not active_only else PeerAccess.READ_PUBLIC
        )
        canonical_id = resolve_peer_ref(
            peer_ref, str(iface_id), access=resolve_access, conn=conn
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

        if slot_ip is not None:
            _reclaim_inactive_peer_slots(
                iface_id,
                conn,
                ip=slot_ip,
                replaced_by_peer_id=canonical_id,
            )

        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface ID {iface_id} not found")

        effective_role = (
            _validate_role(role)
            if role is not None
            else str(before["role"] or PeerRole.ENDPOINT)
        )
        effective_routed: str | None | UnsetType = UNSET
        if clear_routed_networks:
            effective_routed = None
        elif routed_networks is not None:
            effective_routed = _normalize_routed_networks(
                routed_networks, address_pool=str(iface["address_pool"])
            )
        elif role is not None and effective_role == PeerRole.ENDPOINT:
            effective_routed = None

        effective_policy = (
            _validate_allowed_ips_policy(allowed_ips_policy)
            if allowed_ips_policy is not None
            else str(before["allowed_ips_policy"] or AllowedIpsPolicy.VPN_ONLY)
        )

        effective_custom: str | None | UnsetType = UNSET
        if clear_custom_allowed_ips:
            effective_custom = None
        elif custom_allowed_ips is not None:
            effective_custom = _normalize_custom_allowed_ips(custom_allowed_ips)
        elif (
            allowed_ips_policy is not None
            and effective_policy != AllowedIpsPolicy.CUSTOM
        ):
            effective_custom = None

        if effective_routed is UNSET:
            current_routed = before["routed_networks"]
            resolved_routed = (
                str(current_routed) if current_routed is not None else None
            )
        elif effective_routed is None:
            resolved_routed = None
        else:
            resolved_routed = str(effective_routed)

        if effective_custom is UNSET:
            current_custom = before["custom_allowed_ips"]
            resolved_custom = (
                str(current_custom) if current_custom is not None else None
            )
        elif effective_custom is None:
            resolved_custom = None
        else:
            resolved_custom = str(effective_custom)

        _resolve_peer_routing_for_write(
            role=effective_role,
            routed_networks=resolved_routed,
            allowed_ips_policy=effective_policy,
            custom_allowed_ips=resolved_custom,
            address_pool=str(iface["address_pool"]),
        )

        prospective_peer = dict(peer)
        if ip_address is not None:
            prospective_peer["ip_address"] = str(validated_ip)
        if normalized_expires is not UNSET:
            prospective_peer["expires_at"] = normalized_expires
        prospective_peer["role"] = effective_role
        prospective_peer["routed_networks"] = resolved_routed
        prospective_peer["allowed_ips_policy"] = effective_policy
        prospective_peer["custom_allowed_ips"] = resolved_custom
        if integrity.is_peer_active(prospective_peer):
            integrity.assert_peer_activation(
                prospective_peer,
                iface,
                conn=conn,
                exclude_peer_id=canonical_id,
            )
        elif ip_address is not None:
            integrity.assert_peer_slot_invariants(
                prospective_peer,
                iface,
                conn=conn,
                exclude_peer_id=canonical_id,
            )

        try:
            db.update_peer(
                canonical_id,
                ip_address=validated_ip,
                dns=normalized_dns,
                desc=normalized_desc,
                mtu=normalized_mtu,
                keepalive=normalized_keepalive,
                expires_at=normalized_expires,
                role=effective_role if role is not None else UNSET,
                routed_networks=effective_routed,
                allowed_ips_policy=(
                    effective_policy if allowed_ips_policy is not None else UNSET
                ),
                custom_allowed_ips=effective_custom,
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
        "node": str(updated["name"]),
        "node_id": str(updated["node_id"]),
        "ip_address": str(updated["ip_address"]),
        "dns": effective_dns,
        "dns_override": updated["dns"],
        "desc": updated["desc"],
        "mtu": _effective_peer_mtu(updated, iface),
        "mtu_override": updated["mtu"],
        "keepalive": _effective_peer_keepalive(updated, iface),
        "keepalive_override": updated["keepalive"],
        "expires_at": updated["expires_at"],
        "role": str(updated["role"] or PeerRole.ENDPOINT),
        "routed_networks": updated["routed_networks"],
        "allowed_ips_policy": str(
            updated["allowed_ips_policy"] or AllowedIpsPolicy.VPN_ONLY
        ),
        "custom_allowed_ips": updated["custom_allowed_ips"],
        "hints": list(dict.fromkeys(hints)),
    }
