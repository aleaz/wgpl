"""Peer activation and database integrity invariants."""

from __future__ import annotations

import base64
import datetime
import ipaddress
import re
import sqlite3
from collections.abc import Mapping
from typing import Any, Literal

from . import db
from .exceptions import (
    InvalidPeerIpError,
    PeerAlreadyExistsError,
    PeersOutsidePoolError,
    WgplException,
)

ExportMode = Literal["server", "client"]

_PEER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
_WIRE_MTU_MIN = 1280
_WIRE_MTU_MAX = 65535
_WIRE_KEEPALIVE_MAX = 65535


def _peer_keys(peer: sqlite3.Row | Mapping[str, object]) -> Any:
    if isinstance(peer, sqlite3.Row):
        return peer.keys()
    return peer.keys()


def _parse_expires_at(value: str) -> datetime.datetime:
    """Parse expires_at from DB; treat naive timestamps as UTC."""
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def is_peer_deleted(peer: sqlite3.Row | Mapping[str, object]) -> bool:
    """Return True when deleted_at is set to a non-empty timestamp."""
    if "deleted_at" not in _peer_keys(peer):
        return False
    deleted_at = peer["deleted_at"]
    if deleted_at is None:
        return False
    return str(deleted_at).strip() != ""


def is_peer_active(peer: sqlite3.Row | Mapping[str, object]) -> bool:
    """Return True if the peer is not soft-deleted and not expired."""
    if is_peer_deleted(peer):
        return False
    expires_at_str = peer["expires_at"] if "expires_at" in _peer_keys(peer) else None
    if expires_at_str is not None:
        try:
            expires_at = _parse_expires_at(str(expires_at_str))
        except ValueError:
            return False
        if expires_at <= datetime.datetime.now(datetime.timezone.utc):
            return False
    return True


def corrupt_expires_at(peer: sqlite3.Row | Mapping[str, object]) -> bool:
    """Return True when expires_at is set but not a valid ISO timestamp."""
    if is_peer_deleted(peer):
        return False
    expires_at_str = peer["expires_at"] if "expires_at" in _peer_keys(peer) else None
    if expires_at_str is None:
        return False
    try:
        _parse_expires_at(str(expires_at_str))
    except ValueError:
        return True
    return False


def parse_future_duration(duration: str) -> datetime.datetime:
    """Parse a duration string and require a strictly future expiration time."""
    match = re.match(r"^(\d+)([dh])$", duration)
    if not match:
        raise WgplException(
            f"Invalid duration format: '{duration}'. Expected format like '7d' or '24h'."
        )

    value = int(match.group(1))
    if value == 0:
        raise WgplException(f"Duration must be greater than zero, got '{duration}'.")

    unit = match.group(2)
    delta = (
        datetime.timedelta(days=value)
        if unit == "d"
        else datetime.timedelta(hours=value)
    )
    expires_at = datetime.datetime.now(datetime.timezone.utc) + delta
    if expires_at <= datetime.datetime.now(datetime.timezone.utc):
        raise WgplException(
            f"Duration '{duration}' must yield a future expiration time."
        )
    return expires_at


def validate_wire_safe_text(value: str, field: str) -> None:
    """Reject values that would break WireGuard INI line-oriented format."""
    if any(ord(ch) < 0x20 and ch not in {"\t"} for ch in value):
        raise WgplException(f"{field} contains unsafe control characters")
    if "\n" in value or "\r" in value:
        raise WgplException(f"{field} must not contain newlines")


def validate_wire_mtu(value: object, *, field: str = "mtu") -> int:
    """Validate MTU for WireGuard configuration export."""
    try:
        mtu = int(str(value))
    except (TypeError, ValueError) as exc:
        raise WgplException(f"{field} must be an integer") from exc
    if not (_WIRE_MTU_MIN <= mtu <= _WIRE_MTU_MAX):
        raise WgplException(
            f"{field} must be between {_WIRE_MTU_MIN} and {_WIRE_MTU_MAX}, got {mtu}"
        )
    return mtu


def validate_wire_keepalive(value: object, *, field: str = "keepalive") -> int:
    """Validate PersistentKeepalive for WireGuard configuration export."""
    try:
        keepalive = int(str(value))
    except (TypeError, ValueError) as exc:
        raise WgplException(f"{field} must be an integer") from exc
    if not (0 <= keepalive <= _WIRE_KEEPALIVE_MAX):
        raise WgplException(
            f"{field} must be between 0 and {_WIRE_KEEPALIVE_MAX}, got {keepalive}"
        )
    return keepalive


def _validate_optional_wire_mtu(
    row: sqlite3.Row | Mapping[str, object], field: str
) -> None:
    if field in _peer_keys(row) and row[field] is not None:
        validate_wire_mtu(row[field], field=field)


def _validate_optional_wire_keepalive(
    row: sqlite3.Row | Mapping[str, object], field: str
) -> None:
    if field in _peer_keys(row) and row[field] is not None:
        validate_wire_keepalive(row[field], field=field)


def validate_wire_public_key(key: str) -> None:
    """Validate public key format and wire-safe encoding."""
    validate_wire_safe_text(key, "public_key")
    try:
        decoded = base64.b64decode(key.encode("utf-8"), validate=True)
        if len(decoded) != 32:
            raise WgplException(
                "public_key must decode to exactly 32 bytes for WireGuard"
            )
    except WgplException:
        raise
    except Exception as exc:
        raise WgplException("public_key must be valid Base64") from exc


def validate_wire_private_key(key: str) -> None:
    """Validate private key format for client configuration export."""
    validate_wire_safe_text(key, "private_key")
    try:
        decoded = base64.b64decode(key.encode("utf-8"), validate=True)
        if len(decoded) != 32:
            raise WgplException(
                "private_key must decode to exactly 32 bytes for WireGuard"
            )
    except WgplException:
        raise
    except Exception as exc:
        raise WgplException("private_key must be valid Base64") from exc


def _parse_interface_network(
    iface: sqlite3.Row | Mapping[str, object],
) -> ipaddress.IPv4Network:
    pool = str(iface["address_pool"])
    try:
        return ipaddress.IPv4Network(pool, strict=False)
    except ValueError as exc:
        raise WgplException(f"Invalid address pool '{pool}'") from exc


def assert_exportable_interface(iface: sqlite3.Row | Mapping[str, object]) -> None:
    """Validate all interface fields required for WireGuard export."""
    validate_wire_interface_fields(iface)
    _parse_interface_network(iface)


def assert_exportable_peer(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    *,
    mode: ExportMode,
) -> None:
    """Validate all peer fields interpolated into WireGuard configuration."""
    name = str(peer["name"])
    if not _PEER_NAME_RE.match(name):
        raise WgplException(f"Peer name '{name}' is not valid for export")
    validate_wire_public_key(str(peer["public_key"]))

    ip = str(peer["ip_address"])
    validate_wire_safe_text(ip, "ip_address")
    network = _parse_interface_network(iface)
    validate_peer_ip_in_pool(ip, network)

    psk = peer["preshared_key"] if "preshared_key" in _peer_keys(peer) else None
    if psk:
        validate_wire_safe_text(str(psk), "preshared_key")
    _validate_optional_wire_mtu(peer, "mtu")
    _validate_optional_wire_keepalive(peer, "keepalive")

    if mode == "client":
        validate_wire_private_key(str(peer["private_key"]))
        peer_dns = peer["dns"] if "dns" in _peer_keys(peer) else None
        iface_dns = iface["dns"] if "dns" in iface.keys() else None
        effective_dns = peer_dns if peer_dns is not None else iface_dns
        if effective_dns:
            validate_wire_safe_text(str(effective_dns), "dns")


def validate_wire_peer_fields(peer: sqlite3.Row | Mapping[str, object]) -> None:
    """Validate peer wire-safe text fields (activation and row scans)."""
    name = str(peer["name"])
    if not _PEER_NAME_RE.match(name):
        raise WgplException(f"Peer name '{name}' is not valid for activation")
    validate_wire_public_key(str(peer["public_key"]))
    validate_wire_safe_text(str(peer["ip_address"]), "ip_address")
    psk = peer["preshared_key"] if "preshared_key" in _peer_keys(peer) else None
    if psk:
        validate_wire_safe_text(str(psk), "preshared_key")
    _validate_optional_wire_mtu(peer, "mtu")
    _validate_optional_wire_keepalive(peer, "keepalive")


def validate_wire_interface_fields(iface: sqlite3.Row | Mapping[str, object]) -> None:
    """Validate interface fields embedded in WireGuard configuration output."""
    name = str(iface["name"])
    if not _PEER_NAME_RE.match(name):
        raise WgplException(f"Interface name '{name}' is not valid for export")
    validate_wire_public_key(str(iface["public_key"]))
    validate_wire_safe_text(str(iface["endpoint"]), "endpoint")
    validate_wire_safe_text(str(iface["address_pool"]), "address_pool")
    port = int(str(iface["port"]))
    if not (1 <= port <= 65535):
        raise WgplException(f"Port must be between 1 and 65535, got {port}")
    _validate_optional_wire_mtu(iface, "mtu")
    _validate_optional_wire_keepalive(iface, "keepalive")


def validate_peer_ip_in_pool(ip: str, network: ipaddress.IPv4Network) -> None:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise InvalidPeerIpError(f"Invalid IP address '{ip}'") from exc

    host_ips = {str(host) for host in network.hosts()}
    if ip not in host_ips:
        raise InvalidPeerIpError(f"IP {ip} is not a host in pool {network}")

    try:
        if ip == str(network[1]):
            raise InvalidPeerIpError(f"IP {ip} is reserved for the interface gateway")
    except IndexError:
        pass


def assert_peer_activation(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    *,
    conn: sqlite3.Connection,
    exclude_peer_id: str | None = None,
) -> None:
    """Ensure a peer about to become active satisfies all activation invariants."""
    if not is_peer_active(peer):
        return

    assert_exportable_peer(peer, iface, mode="server")

    iface_id = int(str(peer["interface_id"]))
    peer_id = str(peer["id"])
    peer_name = str(peer["name"])
    ip = str(peer["ip_address"])

    for other in db.list_peers(iface_id, conn=conn):
        if exclude_peer_id is not None and str(other["id"]) == exclude_peer_id:
            continue
        if str(other["id"]) == peer_id:
            continue
        if not is_peer_active(other):
            continue
        if str(other["ip_address"]) == ip:
            raise PeerAlreadyExistsError(
                f"IP {ip} is already assigned to active peer '{other['name']}'"
            )
        if str(other["name"]) == peer_name:
            raise PeerAlreadyExistsError(
                f"Peer name '{peer_name}' already exists in this interface."
            )


def assert_peer_slot_invariants(
    peer: sqlite3.Row | Mapping[str, object],
    iface: sqlite3.Row | Mapping[str, object],
    *,
    conn: sqlite3.Connection,
    exclude_peer_id: str | None = None,
) -> None:
    """Validate name/IP constraints for inactive peer updates without activation."""
    if is_peer_active(peer):
        return

    network = _parse_interface_network(iface)
    ip = str(peer["ip_address"])
    validate_peer_ip_in_pool(ip, network)
    validate_wire_safe_text(ip, "ip_address")

    iface_id = int(str(peer["interface_id"]))
    peer_id = str(peer["id"])
    peer_name = str(peer["name"])

    for other in db.list_peers(iface_id, conn=conn):
        if exclude_peer_id is not None and str(other["id"]) == exclude_peer_id:
            continue
        if str(other["id"]) == peer_id:
            continue
        if not is_peer_active(other):
            continue
        if str(other["ip_address"]) == ip:
            raise PeerAlreadyExistsError(
                f"IP {ip} is already assigned to active peer '{other['name']}'"
            )
        if str(other["name"]) == peer_name:
            raise PeerAlreadyExistsError(
                f"Peer name '{peer_name}' already exists in this interface."
            )


def validate_non_deleted_peers_in_pool(
    interface_name: str,
    pool_cidr: str,
    conn: sqlite3.Connection,
    *,
    resolve_interface_ref: Any,
) -> None:
    """Reject pool changes that orphan any non-soft-deleted peer outside the CIDR."""
    network = ipaddress.IPv4Network(pool_cidr, strict=False)
    conflicts: list[dict[str, str]] = []

    iface_id = resolve_interface_ref(interface_name, conn=conn)

    for peer in db.list_peers(iface_id, conn=conn):
        if is_peer_deleted(peer):
            continue
        ip = str(peer["ip_address"])
        try:
            validate_peer_ip_in_pool(ip, network)
        except InvalidPeerIpError as exc:
            conflicts.append(
                {"name": str(peer["name"]), "ip_address": ip, "detail": str(exc)}
            )

    if conflicts:
        raise PeersOutsidePoolError(interface_name, conflicts)


def validate_database(
    conn: sqlite3.Connection | None = None,
    *,
    full: bool = False,
) -> dict[str, str | list[dict[str, str | None]]]:
    """Validate stored wire-format fields; full=True checks every row."""
    issues: list[dict[str, str | None]] = []

    for iface in db.list_interfaces(conn=conn):
        iface_name = str(iface["name"])
        iface_id = int(str(iface["id"]))

        if full:
            try:
                assert_exportable_interface(iface)
            except WgplException as exc:
                issues.append(
                    {
                        "interface": iface_name,
                        "peer": None,
                        "code": "invalid_wire_fields",
                        "detail": str(exc),
                    }
                )

        for peer in db.list_peers(iface_id, conn=conn):
            peer_name = str(peer["name"])
            if not full:
                if is_peer_deleted(peer):
                    continue
                if not is_peer_active(peer):
                    continue
            try:
                assert_exportable_peer(peer, iface, mode="server")
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
