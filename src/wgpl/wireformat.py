"""WireGuard configuration builders (emit formatting + shared validation/cascade).

Route derivation lives in ``routing.py``. Callers must pass the emit gate in
``core.py`` (``assert_exportable_*``) before building configs. This module
normalizes AllowedIPs and cascades DNS/MTU/keepalive for client output.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from collections.abc import Mapping

from . import integrity
from .exceptions import WgplException

_INTERFACE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def validate_allowed_ips(allowed_ips: str) -> str:
    """Validate AllowedIPs for client export (comma-separated networks)."""
    normalized_parts: list[str] = []
    for part in allowed_ips.split(","):
        candidate = part.strip()
        if not candidate:
            raise WgplException("AllowedIPs entries cannot be empty")
        integrity.validate_wire_safe_text(candidate, "AllowedIPs")
        try:
            normalized_parts.append(str(ipaddress.IPv4Network(candidate, strict=False)))
        except ValueError as exc:
            raise WgplException(
                f"Invalid AllowedIPs format '{candidate}' (WGPL supports IPv4 only)"
            ) from exc
    return ",".join(normalized_parts)


def build_server_config(
    iface: sqlite3.Row | Mapping[str, object],
    peer_allowed_ips: list[tuple[sqlite3.Row | Mapping[str, object], list[str]]],
) -> str:
    """Build declarative server syncconf content for active peers only."""
    name = str(iface["name"])
    if not _INTERFACE_NAME_RE.match(name):
        raise WgplException(f"Interface name '{name}' is not valid for export")

    conf_lines: list[str] = []
    mtu = iface["mtu"] if "mtu" in iface.keys() else None
    if mtu is not None:
        conf_lines.append(f"MTU = {mtu}")
        conf_lines.append("")

    for peer, allowed_ips in peer_allowed_ips:
        conf_lines.append("[Peer]")
        conf_lines.append(f"PublicKey = {peer['public_key']}")
        if peer["preshared_key"]:
            conf_lines.append(f"PresharedKey = {peer['preshared_key']}")
        normalized_allowed_ips = validate_allowed_ips(",".join(allowed_ips))
        conf_lines.append(f"AllowedIPs = {normalized_allowed_ips}")
        conf_lines.append("")

    return "\n".join(conf_lines)


def build_client_config(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    allowed_ips: str,
) -> str:
    """Build a WireGuard client configuration from pre-validated rows."""
    normalized_allowed_ips = validate_allowed_ips(allowed_ips)
    network = ipaddress.IPv4Network(str(iface["address_pool"]), strict=False)
    endpoint = str(iface["endpoint"])
    port = int(str(iface["port"]))

    config_lines = [
        "[Interface]",
        f"PrivateKey = {peer['private_key']}",
        f"Address = {peer['ip_address']}/{network.prefixlen}",
    ]

    peer_dns = peer["dns"] if "dns" in peer.keys() else None
    iface_dns = iface["dns"] if "dns" in iface.keys() else None
    effective_dns = peer_dns if peer_dns is not None else iface_dns
    if effective_dns:
        config_lines.append(f"DNS = {effective_dns}")

    peer_mtu = peer["mtu"] if "mtu" in peer.keys() else None
    iface_mtu = iface["mtu"] if "mtu" in iface.keys() else None
    effective_mtu = peer_mtu if peer_mtu is not None else iface_mtu
    if effective_mtu is not None:
        config_lines.append(f"MTU = {effective_mtu}")

    config_lines.extend(["", "[Peer]", f"PublicKey = {iface['public_key']}"])

    psk = peer["preshared_key"] if "preshared_key" in peer.keys() else None
    if psk:
        config_lines.append(f"PresharedKey = {psk}")

    config_lines.extend(
        [
            f"Endpoint = {endpoint}:{port}",
            f"AllowedIPs = {normalized_allowed_ips}",
        ]
    )

    peer_keepalive = peer["keepalive"] if "keepalive" in peer.keys() else None
    iface_keepalive = iface["keepalive"] if "keepalive" in iface.keys() else None
    effective_keepalive = (
        peer_keepalive if peer_keepalive is not None else iface_keepalive
    )
    if effective_keepalive is not None:
        config_lines.append(f"PersistentKeepalive = {effective_keepalive}")

    config_lines.append("")

    return "\n".join(config_lines)
