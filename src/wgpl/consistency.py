"""Database consistency validation without mutation."""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Mapping
from typing import Literal, cast

from . import db
from . import integrity
from . import routing
from .refs import resolve_interface_ref
from .validators import validate_dns
from .exceptions import (
    InterfaceNotFoundError,
    InvalidDnsError,
    InvalidPeerIpError,
    WgplException,
)

IssueSeverity = Literal["error", "warning"]


def _issue(
    *,
    interface: str,
    peer: str | None,
    code: str,
    detail: str,
    severity: IssueSeverity = "error",
) -> dict[str, str | None]:
    return {
        "interface": interface,
        "peer": peer,
        "code": code,
        "detail": detail,
        "severity": severity,
    }


def _effective_keepalive(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
) -> int | None:
    peer_keys = peer.keys() if isinstance(peer, sqlite3.Row) else peer.keys()
    iface_keys = iface.keys() if isinstance(iface, sqlite3.Row) else iface.keys()
    peer_keepalive = peer["keepalive"] if "keepalive" in peer_keys else None
    if peer_keepalive is not None:
        return int(str(peer_keepalive))
    iface_keepalive = iface["keepalive"] if "keepalive" in iface_keys else None
    if iface_keepalive is not None:
        return int(str(iface_keepalive))
    return None


def _peer_routed_networks(
    peer: sqlite3.Row | Mapping[str, object],
) -> list[ipaddress.IPv4Network]:
    keys = peer.keys() if isinstance(peer, sqlite3.Row) else peer.keys()
    raw = peer["routed_networks"] if "routed_networks" in keys else None
    if raw is None or str(raw).strip() == "":
        return []
    try:
        return routing.parse_cidr_list(str(raw))
    except WgplException:
        return []


def _validate_routing_topology(
    iface: sqlite3.Row,
    peers: list[sqlite3.Row],
    *,
    pool: ipaddress.IPv4Network,
) -> list[dict[str, str | None]]:
    """Validate hub-and-spoke routing intent for one interface."""
    issues: list[dict[str, str | None]] = []
    iface_name = str(iface["name"])
    address_pool = str(iface["address_pool"])

    iface_routed_raw = (
        iface["routed_networks"] if "routed_networks" in iface.keys() else None
    )
    if iface_routed_raw:
        try:
            integrity.validate_routed_networks_list(
                str(iface_routed_raw),
                field="routed_networks",
                address_pool=address_pool,
                tunnel_ip=None,
            )
        except WgplException as exc:
            issues.append(
                _issue(
                    interface=iface_name,
                    peer=None,
                    code="routed_networks_overlaps_pool",
                    detail=str(exc),
                )
            )

    active_subnet_routers: list[sqlite3.Row] = []
    for peer in peers:
        peer_name = str(peer["name"])
        role = (
            str(peer["role"])
            if "role" in peer.keys() and peer["role"] is not None
            else routing.PeerRole.ENDPOINT
        )

        if role == routing.PeerRole.SUBNET_ROUTER:
            if integrity.is_peer_active(peer):
                active_subnet_routers.append(peer)
                routed = _peer_routed_networks(peer)
                if not routed:
                    issues.append(
                        _issue(
                            interface=iface_name,
                            peer=peer_name,
                            code="subnet_router_missing_routed_networks",
                            detail="subnet_router requires routed_networks",
                        )
                    )
                else:
                    try:
                        integrity.validate_routed_networks_list(
                            str(peer["routed_networks"]),
                            field="routed_networks",
                            address_pool=address_pool,
                            tunnel_ip=str(peer["ip_address"]),
                        )
                    except WgplException as exc:
                        issues.append(
                            _issue(
                                interface=iface_name,
                                peer=peer_name,
                                code="routed_networks_overlaps_pool",
                                detail=str(exc),
                            )
                        )
                    if _effective_keepalive(peer, iface) is None:
                        issues.append(
                            _issue(
                                interface=iface_name,
                                peer=peer_name,
                                code="subnet_router_missing_keepalive",
                                detail=(
                                    "subnet_router has no effective PersistentKeepalive; "
                                    "LAN↔LAN via hub may be intermittent behind NAT"
                                ),
                                severity="warning",
                            )
                        )
            elif (
                not integrity.is_peer_deleted(peer)
                and peer["routed_networks"]
                and get_peer_status_expired(peer)
            ):
                issues.append(
                    _issue(
                        interface=iface_name,
                        peer=peer_name,
                        code="expired_subnet_router_routes_dropped",
                        detail=(
                            "Expired subnet_router no longer advertises routed_networks "
                            "on hub or peer exports"
                        ),
                        severity="warning",
                    )
                )

    for left_idx, left in enumerate(active_subnet_routers):
        left_networks = _peer_routed_networks(left)
        for right in active_subnet_routers[left_idx + 1 :]:
            right_networks = _peer_routed_networks(right)
            for left_net in left_networks:
                for right_net in right_networks:
                    if left_net.overlaps(right_net):
                        issues.append(
                            _issue(
                                interface=iface_name,
                                peer=str(left["name"]),
                                code="overlapping_routed_networks",
                                detail=(
                                    f"Routed network {left_net} overlaps active peer "
                                    f"'{right['name']}' prefix {right_net}"
                                ),
                            )
                        )

    if len(active_subnet_routers) >= 2:
        active_peers = [p for p in peers if integrity.is_peer_active(p)]
        for router in active_subnet_routers:
            router_name = str(router["name"])
            policy = (
                str(router["allowed_ips_policy"])
                if "allowed_ips_policy" in router.keys()
                and router["allowed_ips_policy"] is not None
                else routing.AllowedIpsPolicy.VPN_ONLY
            )
            others = [
                p for p in active_subnet_routers if str(p["id"]) != str(router["id"])
            ]
            other_lans = {
                str(net) for other in others for net in _peer_routed_networks(other)
            }
            if not other_lans:
                continue
            if policy != routing.AllowedIpsPolicy.ALL_REMOTE_NETWORKS:
                issues.append(
                    _issue(
                        interface=iface_name,
                        peer=router_name,
                        code="asymmetric_remote_access",
                        detail=(
                            f"Peer '{router_name}' uses allowed_ips_policy={policy!s} "
                            "but other subnet routers advertise LANs; use "
                            "all_remote_networks for bidirectional LAN↔LAN via hub"
                        ),
                        severity="warning",
                    )
                )
                continue
            derived = set(
                routing.resolve_client_allowed_ips(router, iface, active_peers)
            )
            missing = sorted(other_lans - derived)
            if missing:
                issues.append(
                    _issue(
                        interface=iface_name,
                        peer=router_name,
                        code="lan_to_lan_incomplete",
                        detail=(
                            "Derived client AllowedIPs missing remote LAN(s): "
                            + ", ".join(missing)
                        ),
                        severity="warning",
                    )
                )

    return issues


def get_peer_status_expired(peer: sqlite3.Row | Mapping[str, object]) -> bool:
    """Return True when the peer is expired but not soft-deleted."""
    if integrity.is_peer_deleted(peer):
        return False
    return not integrity.is_peer_active(peer)


def validate_state(
    interface: str | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> dict[str, str | list[dict[str, str | None]]]:
    """Validate DB consistency without mutating state."""
    issues: list[dict[str, str | None]] = []

    if interface is not None:
        iface_id = resolve_interface_ref(interface, conn=conn)
        iface = db.get_interface(iface_id, conn=conn)
        if not iface:
            raise InterfaceNotFoundError(f"Interface {interface} not found")
        interfaces = [iface]
    else:
        interfaces = db.list_interfaces(conn=conn)

    for iface in interfaces:
        iface_name = str(iface["name"])
        pool = str(iface["address_pool"])
        try:
            network = ipaddress.IPv4Network(pool, strict=False)
        except ValueError as exc:
            issues.append(
                {
                    "interface": iface_name,
                    "peer": None,
                    "code": "invalid_address_pool",
                    "detail": f"Invalid address pool '{pool}': {exc}",
                }
            )
            continue

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

        try:
            integrity.validate_wire_interface_fields(iface)
        except WgplException as exc:
            issues.append(
                {
                    "interface": iface_name,
                    "peer": None,
                    "code": "invalid_wire_fields",
                    "detail": str(exc),
                }
            )

        seen_ips: dict[str, str] = {}
        seen_names: dict[str, str] = {}
        for peer in db.list_peers(iface["id"], conn=conn):
            if integrity.corrupt_expires_at(peer):
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": str(peer["name"]),
                        "code": "corrupt_expires_at",
                        "detail": f"Peer {peer['name']} has invalid expires_at",
                    }
                )
            if not integrity.is_peer_active(peer):
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
                integrity.validate_peer_ip_in_pool(ip, network)
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

        issues.extend(
            _validate_routing_topology(
                iface, list(db.list_peers(iface["id"], conn=conn)), pool=network
            )
        )

    errors = [i for i in issues if i.get("severity", "error") == "error"]
    warnings = [i for i in issues if i.get("severity") == "warning"]
    if errors:
        status = "error"
    elif warnings:
        status = "warning"
    else:
        status = "ok"
    return {"status": status, "issues": issues}


def assert_database_valid(interface: str | None = None) -> None:
    """Raise when the database fails consistency checks (errors only; warnings pass)."""
    result = validate_state(interface)
    if result["status"] != "error":
        return
    issues = cast(list[dict[str, str | None]], result["issues"])
    error_issues = [i for i in issues if i.get("severity", "error") == "error"]
    details = "; ".join(
        f"{issue.get('interface')}/{issue.get('peer')}: "
        f"{issue.get('code')} — {issue.get('detail')}"
        for issue in error_issues
    )
    raise WgplException(f"Database validation failed: {details}")
