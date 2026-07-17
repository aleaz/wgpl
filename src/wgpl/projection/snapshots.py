"""Immutable values crossing the application-to-projection boundary."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServerPeerSnapshot:
    public_key: str
    preshared_key: str | None
    allowed_ips: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServerSnapshot:
    interface_name: str
    mtu: int | None
    peers: tuple[ServerPeerSnapshot, ...]


@dataclass(frozen=True, slots=True)
class ClientSnapshot:
    private_key: str
    ip_address: str
    address_prefix_length: int
    dns: str | None
    mtu: int | None
    server_public_key: str
    preshared_key: str | None
    endpoint: str
    port: int
    allowed_ips: tuple[str, ...]
    keepalive: int | None
