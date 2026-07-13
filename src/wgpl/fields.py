"""Shared field patterns and peer-over-interface cascade helpers.

Leaf module: no imports from other ``wgpl`` packages (avoids cycles between
``validators``, ``wireformat``, and ``integrity``).
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping

NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
NAME_MAX_LEN = 64


def row_field(row: sqlite3.Row | Mapping[str, object], field: str) -> object | None:
    """Return ``row[field]`` when present, else ``None``."""
    keys = row.keys()
    return row[field] if field in keys else None


def effective_dns(peer_dns: str | None, iface_dns: str | None) -> str | None:
    """Return peer DNS override or interface default (empty string falls back)."""
    if peer_dns:
        return str(peer_dns)
    if iface_dns:
        return str(iface_dns)
    return None


def effective_mtu(
    peer_mtu: object | None, iface_mtu: object | None
) -> int | None:
    """Return peer MTU override or interface default."""
    if peer_mtu is not None:
        return int(str(peer_mtu))
    if iface_mtu is not None:
        return int(str(iface_mtu))
    return None


def effective_keepalive(
    peer_keepalive: object | None, iface_keepalive: object | None
) -> int | None:
    """Return peer keepalive override or interface default."""
    if peer_keepalive is not None:
        return int(str(peer_keepalive))
    if iface_keepalive is not None:
        return int(str(iface_keepalive))
    return None


def effective_peer_dns(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
) -> str | None:
    peer_dns = row_field(peer, "dns")
    iface_dns = row_field(iface, "dns")
    return effective_dns(
        str(peer_dns) if peer_dns is not None else None,
        str(iface_dns) if iface_dns is not None else None,
    )


def effective_peer_mtu(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
) -> int | None:
    return effective_mtu(row_field(peer, "mtu"), row_field(iface, "mtu"))


def effective_peer_keepalive(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
) -> int | None:
    return effective_keepalive(
        row_field(peer, "keepalive"), row_field(iface, "keepalive")
    )
