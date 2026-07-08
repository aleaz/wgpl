"""Routing intent derivation for WireGuard AllowedIPs (pure functions, no I/O)."""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Mapping, Sequence
from enum import StrEnum

from .exceptions import WgplException


class PeerRole(StrEnum):
    ENDPOINT = "endpoint"
    SUBNET_ROUTER = "subnet_router"


class AllowedIpsPolicy(StrEnum):
    VPN_ONLY = "vpn_only"
    SPLIT_TUNNEL = "split_tunnel"
    ALL_REMOTE_NETWORKS = "all_remote_networks"
    FULL_TUNNEL = "full_tunnel"
    CUSTOM = "custom"


DEFAULT_ROUTE = ipaddress.IPv4Network("0.0.0.0/0")


def _row_keys(row: sqlite3.Row | Mapping[str, object]) -> set[str]:
    if isinstance(row, sqlite3.Row):
        return set(row.keys())
    return set(row.keys())


def _peer_role(peer: sqlite3.Row | Mapping[str, object]) -> str:
    if "role" not in _row_keys(peer):
        return PeerRole.ENDPOINT
    role = peer["role"]
    return str(role) if role is not None else PeerRole.ENDPOINT


def _peer_identity(peer: sqlite3.Row | Mapping[str, object]) -> str:
    """Return the device identity for own-LAN exclusion (node_id, else peer id)."""
    if "node_id" in _row_keys(peer) and peer["node_id"] is not None:
        return f"node:{peer['node_id']}"
    return f"peer:{peer['id']}"


def _allowed_ips_policy(peer: sqlite3.Row | Mapping[str, object]) -> str:
    if "allowed_ips_policy" not in _row_keys(peer):
        return AllowedIpsPolicy.VPN_ONLY
    policy = peer["allowed_ips_policy"]
    return str(policy) if policy is not None else AllowedIpsPolicy.VPN_ONLY


def parse_cidr_list(value: str | None) -> list[ipaddress.IPv4Network]:
    """Parse a comma-separated IPv4 CIDR list; reject empty entries."""
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    networks: list[ipaddress.IPv4Network] = []
    for part in text.split(","):
        candidate = part.strip()
        if not candidate:
            raise WgplException("CIDR list entries cannot be empty")
        try:
            networks.append(ipaddress.IPv4Network(candidate, strict=False))
        except ValueError as exc:
            raise WgplException(f"Invalid CIDR '{candidate}'") from exc
    return networks


def format_cidr_list(networks: Sequence[ipaddress.IPv4Network]) -> str:
    """Format networks as a stable, deduplicated comma-separated CIDR string."""
    unique = {str(network) for network in networks}
    ordered = sorted(
        unique,
        key=lambda item: (
            ipaddress.IPv4Network(item).network_address,
            ipaddress.IPv4Network(item).prefixlen,
        ),
    )
    return ",".join(ordered)


def normalize_cidr_list(value: str) -> str:
    """Parse, deduplicate, and normalize a comma-separated CIDR list for storage."""
    networks = parse_cidr_list(value)
    if not networks:
        raise WgplException("CIDR list cannot be empty")
    return format_cidr_list(networks)


def collapse_redundant_prefixes(
    networks: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Drop prefixes that are contained in another prefix already kept."""
    ordered = sorted(
        networks, key=lambda net: (net.prefixlen, int(net.network_address))
    )
    kept: list[ipaddress.IPv4Network] = []
    for net in ordered:
        if any(net.subnet_of(existing) and net != existing for existing in kept):
            continue
        kept.append(net)
    return kept


def resolve_hub_allowed_ips(peer: sqlite3.Row | Mapping[str, object]) -> list[str]:
    """Derive hub [Peer] AllowedIPs: tunnel /32 plus routed networks for subnet routers."""
    tunnel_ip = str(peer["ip_address"])
    result = [f"{tunnel_ip}/32"]
    if _peer_role(peer) != PeerRole.SUBNET_ROUTER:
        return result

    routed = peer["routed_networks"] if "routed_networks" in _row_keys(peer) else None
    for network in parse_cidr_list(str(routed) if routed else None):
        cidr = str(network)
        if cidr not in result:
            result.append(cidr)
    return result


def resolve_client_allowed_ips(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    active_peers: Sequence[sqlite3.Row | Mapping[str, object]],
) -> list[str]:
    """Derive client [Peer] AllowedIPs from allowed_ips_policy and topology."""
    policy = _allowed_ips_policy(peer)
    if policy == AllowedIpsPolicy.FULL_TUNNEL:
        return ["0.0.0.0/0"]

    if policy == AllowedIpsPolicy.CUSTOM:
        custom = (
            peer["custom_allowed_ips"]
            if "custom_allowed_ips" in _row_keys(peer)
            else None
        )
        if custom is None:
            raise WgplException(
                "custom_allowed_ips is required when allowed_ips_policy is custom"
            )
        collapsed = collapse_redundant_prefixes(parse_cidr_list(str(custom)))
        return [
            str(network)
            for network in sorted(
                collapsed, key=lambda net: (net.network_address, net.prefixlen)
            )
        ]

    pool = ipaddress.IPv4Network(str(iface["address_pool"]), strict=False)
    networks: list[ipaddress.IPv4Network] = [pool]

    if policy in (
        AllowedIpsPolicy.SPLIT_TUNNEL,
        AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
    ):
        iface_routed = (
            iface["routed_networks"] if "routed_networks" in _row_keys(iface) else None
        )
        networks.extend(parse_cidr_list(str(iface_routed) if iface_routed else None))

    if policy == AllowedIpsPolicy.ALL_REMOTE_NETWORKS:
        own_key = _peer_identity(peer)
        own_routed = {
            str(network)
            for network in parse_cidr_list(
                str(peer["routed_networks"])
                if "routed_networks" in _row_keys(peer) and peer["routed_networks"]
                else None
            )
        }
        for other in active_peers:
            if _peer_identity(other) == own_key:
                continue
            if _peer_role(other) != PeerRole.SUBNET_ROUTER:
                continue
            other_routed = (
                other["routed_networks"]
                if "routed_networks" in _row_keys(other)
                else None
            )
            for network in parse_cidr_list(str(other_routed) if other_routed else None):
                cidr = str(network)
                if cidr not in own_routed:
                    networks.append(network)

    collapsed = collapse_redundant_prefixes(networks)
    return [
        str(network)
        for network in sorted(
            collapsed, key=lambda net: (net.network_address, net.prefixlen)
        )
    ]
