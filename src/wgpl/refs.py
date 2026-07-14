"""Peer and interface reference resolution."""

from __future__ import annotations

import sqlite3
from enum import StrEnum

from typing import Any

from . import db
from . import integrity
from .exceptions import (
    AmbiguousInterfaceError,
    AmbiguousNodeIdError,
    InterfaceDisambiguationRequiredError,
    InterfaceNotFoundError,
    NodeNotFoundError,
    PeerInterfaceMismatchError,
    PeerNotFoundError,
    AmbiguousPeerIdError,
)

_MIN_PEER_ID_PREFIX_LEN = 4
_MIN_NODE_ID_PREFIX_LEN = 4
_PEER_ID_HEX_LEN = 32


class PeerAccess(StrEnum):
    READ_PUBLIC = "read_public"
    READ_SENSITIVE = "read_sensitive"
    EXPORT_SECRET = "export_secret"  # nosec B105
    MUTATE = "mutate"


def _requires_interface_disambiguation(access: PeerAccess) -> bool:
    return access in {
        PeerAccess.READ_SENSITIVE,
        PeerAccess.EXPORT_SECRET,
    }


def _active_only(access: PeerAccess) -> bool:
    return access in {PeerAccess.READ_PUBLIC, PeerAccess.EXPORT_SECRET}


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


def _assert_peer_belongs_to_interface(
    peer_id: str,
    iface_id: int | None,
    *,
    interface_label: str | None,
    conn: sqlite3.Connection | None,
) -> None:
    if iface_id is None:
        return
    peer = db.get_peer(peer_id, conn=conn)
    if not peer:
        raise PeerNotFoundError(f"Peer {peer_id} not found")
    if int(peer["interface_id"]) != iface_id:
        label = interface_label or str(iface_id)
        raise PeerInterfaceMismatchError(
            f"Peer {peer_id} does not belong to interface {label}"
        )


def resolve_peer_ref(
    ref: str,
    interface: str | None = None,
    *,
    access: PeerAccess = PeerAccess.READ_PUBLIC,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Resolve a peer reference (full UUID or unique hex prefix) to canonical UUID."""
    resolved_access = access
    normalized = _normalize_peer_ref(ref)

    if not normalized or not all(c in "0123456789abcdef" for c in normalized):
        raise PeerNotFoundError(f"Peer {ref} not found")

    if _requires_interface_disambiguation(resolved_access) and interface is None:
        if len(db.list_interfaces(conn=conn)) > 1:
            raise InterfaceDisambiguationRequiredError(
                "Multiple interfaces in database; specify --interface / -i "
                "when accessing peer secrets or sensitive data."
            )

    active_only = _active_only(resolved_access)
    iface_id = resolve_interface_ref(interface, conn=conn) if interface else None

    if len(normalized) == _PEER_ID_HEX_LEN:
        global_matches = db.find_peers_by_id_prefix(normalized, None, conn=conn)
        if active_only:
            global_matches = [
                peer for peer in global_matches if integrity.is_peer_active(peer)
            ]
        exact = [
            peer
            for peer in global_matches
            if _normalize_peer_ref(peer["id"]) == normalized
        ]
        if len(exact) == 1:
            peer_id = str(exact[0]["id"])
            _assert_peer_belongs_to_interface(
                peer_id, iface_id, interface_label=interface, conn=conn
            )
            return peer_id
        if len(exact) > 1:
            raise AmbiguousPeerIdError(_ambiguous_peer_message(ref, exact))

    if len(normalized) < _MIN_PEER_ID_PREFIX_LEN:
        raise PeerNotFoundError(f"Peer prefix '{ref}' is too short (minimum {_MIN_PEER_ID_PREFIX_LEN} hex characters).")

    matches = db.find_peers_by_id_prefix(normalized, iface_id, conn=conn)
    if active_only:
        matches = [peer for peer in matches if integrity.is_peer_active(peer)]
    if not matches:
        if iface_id is not None:
            global_matches = db.find_peers_by_id_prefix(normalized, None, conn=conn)
            if active_only:
                global_matches = [
                    peer for peer in global_matches if integrity.is_peer_active(peer)
                ]
            if len(global_matches) == 1:
                peer_id = str(global_matches[0]["id"])
                _assert_peer_belongs_to_interface(
                    peer_id, iface_id, interface_label=interface, conn=conn
                )
                return peer_id
            if len(global_matches) > 1:
                raise AmbiguousPeerIdError(
                    _ambiguous_peer_message(ref, global_matches)
                )
        raise PeerNotFoundError(f"Peer {ref} not found")
    if len(matches) == 1:
        peer_id = str(matches[0]["id"])
        _assert_peer_belongs_to_interface(
            peer_id, iface_id, interface_label=interface, conn=conn
        )
        return peer_id
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


def resolve_node_ref(
    ref: str,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Resolve a node reference to its canonical ID.

    Precedence: an exact node name wins; otherwise an all-hex prefix of length
    >= 4 is treated as a node-id prefix. This keeps ``--node <name>`` intuitive
    while still allowing id-prefix lookups.
    """
    node = db.get_node_by_name(ref, conn=conn)
    if node is not None:
        return str(node["id"])

    normalized = ref.replace("-", "").lower()
    if normalized and all(c in "0123456789abcdef" for c in normalized):
        if len(normalized) < _MIN_NODE_ID_PREFIX_LEN:
            raise NodeNotFoundError(f"Node prefix '{ref}' is too short (minimum {_MIN_NODE_ID_PREFIX_LEN} hex characters).")

        matches = db.find_nodes_by_id_prefix(normalized, conn=conn)
        exact = [
            n for n in matches if str(n["id"]).replace("-", "").lower() == normalized
        ]
        if len(exact) == 1:
            return str(exact[0]["id"])
        if len(matches) == 1:
            return str(matches[0]["id"])
        if len(matches) > 1:
            raise AmbiguousNodeIdError(
                f"Node ID prefix '{ref}' is ambiguous ({len(matches)} matches)."
            )
    raise NodeNotFoundError(f"Node {ref} not found")


def get_interface_by_ref(ref: str) -> dict[str, Any]:
    """Resolve an interface name or ID and return its row as a dict."""
    iface_id = resolve_interface_ref(ref)
    iface = db.get_interface(iface_id)
    if not iface:
        raise InterfaceNotFoundError(f"Interface {ref} not found")
    return dict(iface)
