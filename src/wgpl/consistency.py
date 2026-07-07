"""Database consistency validation without mutation."""

from __future__ import annotations

import ipaddress
from typing import cast

from . import db
from . import integrity
from .refs import resolve_interface_ref
from .validators import validate_dns
from .exceptions import (
    InterfaceNotFoundError,
    InvalidDnsError,
    InvalidPeerIpError,
    WgplException,
)


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

    status = "ok" if not issues else "error"
    return {"status": status, "issues": issues}


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
