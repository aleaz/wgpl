"""Audit trail helpers and history queries."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from typing import Any

from . import db
from .refs import (
    PeerAccess,
    _MIN_PEER_ID_PREFIX_LEN,
    _normalize_peer_ref,
    resolve_interface_ref,
    resolve_node_ref,
    resolve_peer_ref,
)
from .exceptions import AmbiguousPeerIdError, PeerNotFoundError

_MAX_EXEC_CMD_LEN = 2_048


def _sanitize_exec_cmd(exec_cmd: str) -> str:
    """Sanitize exec_cmd for storing into audit metadata."""
    sanitized = re.sub(r"[\r\n\t]+", " ", str(exec_cmd))
    sanitized = "".join(ch for ch in sanitized if ch.isprintable())
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    if len(sanitized) > _MAX_EXEC_CMD_LEN:
        sanitized = sanitized[:_MAX_EXEC_CMD_LEN] + "..."
    return sanitized


def _audit_peer_from_row(
    peer: sqlite3.Row,
    event_type: db.AuditEventType,
    conn: sqlite3.Connection,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata_with_context = dict(metadata) if metadata else {}
    node_id = peer["node_id"] if "node_id" in peer.keys() else None
    if node_id is not None:
        metadata_with_context.setdefault("node_id", str(node_id))
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


def _audit_node_event(
    node_id: str,
    node_name: str,
    event_type: db.AuditEventType,
    conn: sqlite3.Connection,
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Create an append-only audit event for a node (global, interface = NULL)."""
    metadata_with_context = dict(metadata) if metadata else {}
    exec_cmd = os.environ.get("WGPL_EXEC_CMD")
    if exec_cmd:
        metadata_with_context["exec_cmd"] = _sanitize_exec_cmd(exec_cmd)

    db.append_audit_event(
        entity_type=db.AuditEntityType.NODE,
        entity_id=str(node_id),
        event_type=event_type,
        interface=None,
        name=node_name,
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
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {"_corrupt": True, "_raw": metadata[:200]}
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
        canonical_id = resolve_peer_ref(
            peer_ref, interface, access=PeerAccess.READ_SENSITIVE
        )
    except PeerNotFoundError:
        normalized = _normalize_peer_ref(peer_ref)
        if len(normalized) < _MIN_PEER_ID_PREFIX_LEN:
            raise PeerNotFoundError(
                f"Peer {peer_ref} not found in current peers or audit history"
            ) from None
        iface_id: int | None = None
        if interface is not None:
            iface_id = resolve_interface_ref(interface)
        else:
            interfaces = db.list_interfaces()
            if len(interfaces) == 1:
                iface_id = int(interfaces[0]["id"])
            elif len(interfaces) > 1:
                raise PeerNotFoundError(
                    f"Peer {peer_ref} not found; specify interface for audit lookup"
                )
        matches = db.find_deleted_peer_id_from_audit(
            normalized, iface_id if iface_id is not None else None
        )
        if not matches:
            raise PeerNotFoundError(
                f"Peer {peer_ref} not found in current peers or audit history"
            )
        if len(matches) > 1:
            raise AmbiguousPeerIdError(
                f"Peer ID prefix '{peer_ref}' is ambiguous in audit history"
            )
        canonical_id = matches[0]
    rows = db.list_audit_events(
        entity_type=db.AuditEntityType.PEER,
        entity_id=canonical_id,
        limit=limit,
        offset=offset,
    )
    return [audit_event_to_dict(row) for row in rows]


def list_node_audit_history(
    ref: str,
    *,
    limit: int = 100,
    offset: int = 0,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return audit events for a node (including after it was removed)."""
    from .exceptions import NodeNotFoundError

    try:
        node_id = resolve_node_ref(ref, conn=conn)
        rows = db.list_audit_events(
            entity_type=db.AuditEntityType.NODE,
            entity_id=node_id,
            limit=limit,
            offset=offset,
            conn=conn,
        )
    except NodeNotFoundError:
        rows = db.list_audit_events(
            entity_type=db.AuditEntityType.NODE,
            entity_id=ref,
            limit=limit,
            offset=offset,
            conn=conn,
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
    from .exceptions import InterfaceNotFoundError

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
