"""IPv4 pool allocation and inactive peer slot reclamation."""

from __future__ import annotations

import ipaddress
import sqlite3

from . import db
from . import integrity
from .audit import _audit_peer_from_row
from .exceptions import (
    InterfaceNotFoundError,
    IpAlreadyInUseError,
    NoAvailableIpsError,
)


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
        if integrity.is_peer_active(peer)
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


def _validate_requested_peer_ip(
    ip: str, network: ipaddress.IPv4Network, used_ips: set[str]
) -> None:
    """Raise if ip is invalid, outside the pool, reserved, or already used."""
    integrity.validate_peer_ip_in_pool(ip, network)

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
        if integrity.is_peer_active(peer) or integrity.is_peer_deleted(peer):
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

                for ip_int in range(max_ip_int + 1, int(network.broadcast_address)):
                    if ip_int not in used_ips_int:
                        return str(ipaddress.IPv4Address(ip_int))

                for ip_int in range(int(network.network_address) + 1, max_ip_int):
                    if ip_int not in used_ips_int:
                        return str(ipaddress.IPv4Address(ip_int))
            except ValueError:
                pass
        raise NoAvailableIpsError(f"No available IPs in pool {network}")

    _validate_requested_peer_ip(requested, network, used_ips)
    return requested
