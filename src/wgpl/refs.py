"""Peer and interface reference resolution."""

from __future__ import annotations

import sqlite3
from enum import StrEnum

from typing import Any

from . import db
from . import integrity
from .exceptions import (
    AmbiguousInterfaceError,
    AmbiguousPeerIdError,
    InterfaceDisambiguationRequiredError,
    InterfaceNotFoundError,
    PeerNotFoundError,
)

_MIN_PEER_ID_PREFIX_LEN = 4
_PEER_ID_HEX_LEN = 32


class PeerResolvePolicy(StrEnum):
    EXPORT_SECRET = "export_secret"  # nosec B105 — resolve policy label, not a secret
    MUTATE_INACTIVE = "mutate_inactive"
    READ_ONLY = "read_only"


def _normalize_peer_ref(ref: str) -> str:
    """Return lowercase hex ID without hyphens."""
    return ref.replace("-", "").lower()


def _format_peer_id_short(peer_id: str) -> str:
    """Return the 12-char hex prefix shown in peer list tables."""
    return _normalize_peer_ref(peer_id)[:12]


def _ambiguous_interface_message(ref: str, matches: list[sqlite3.Row]) -> str:
    lines = [f"Multiple interfaces named '{ref}':"]
    for iface in matches:
        lines.append(
            f"  ID {iface['id']} → {iface['endpoint']}:{iface['port']} ({iface['address_pool']})"
        )
    lines.append(
        f"Specify the interface ID directly, e.g.: wgpl <command> {matches[0]['id']} ..."
    )
    return "\n".join(lines)


def _ambiguous_peer_message(ref: str, matches: list[sqlite3.Row]) -> str:
    candidates = ", ".join(
        f"{_format_peer_id_short(peer['id'])} ({peer['name']})" for peer in matches
    )
    return f"Peer ID prefix '{ref}' is ambiguous. Matches: {candidates}"


def resolve_peer_ref(
    ref: str,
    interface: str | None = None,
    *,
    policy: PeerResolvePolicy = PeerResolvePolicy.READ_ONLY,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Resolve a peer reference (full UUID or unique hex prefix) to canonical UUID."""
    normalized = _normalize_peer_ref(ref)

    if not normalized or not all(c in "0123456789abcdef" for c in normalized):
        raise PeerNotFoundError(f"Peer {ref} not found")

    if policy == PeerResolvePolicy.EXPORT_SECRET and interface is None:
        if len(db.list_interfaces(conn=conn)) > 1:
            raise InterfaceDisambiguationRequiredError(
                "Multiple interfaces in database; specify --interface / -i "
                "when exporting client configuration or secrets."
            )

    active_only = policy != PeerResolvePolicy.MUTATE_INACTIVE

    iface_id = resolve_interface_ref(interface, conn=conn) if interface else None

    if len(normalized) == _PEER_ID_HEX_LEN:
        matches = db.find_peers_by_id_prefix(normalized, iface_id, conn=conn)
        if active_only:
            matches = [peer for peer in matches if integrity.is_peer_active(peer)]
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
        matches = [peer for peer in matches if integrity.is_peer_active(peer)]
    if not matches:
        raise PeerNotFoundError(f"Peer {ref} not found")
    if len(matches) == 1:
        return str(matches[0]["id"])
    raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, matches))


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
