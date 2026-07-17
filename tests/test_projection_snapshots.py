"""Tests for the immutable Stage 1 projection values."""

from dataclasses import FrozenInstanceError, fields

import pytest

from wgpl.projection.snapshots import (
    ClientSnapshot,
    ServerPeerSnapshot,
    ServerSnapshot,
)


def _server_peer() -> ServerPeerSnapshot:
    return ServerPeerSnapshot(
        public_key="server-peer-public",
        preshared_key="server-peer-psk",
        allowed_ips=("10.0.0.2/32", "192.168.10.0/24"),
    )


def _server_snapshot() -> ServerSnapshot:
    return ServerSnapshot(
        interface_name="wg0",
        mtu=1420,
        peers=(_server_peer(),),
    )


def _client_snapshot() -> ClientSnapshot:
    return ClientSnapshot(
        private_key="selected-peer-private",
        ip_address="10.0.0.2",
        address_prefix_length=24,
        dns="1.1.1.1",
        mtu=1380,
        server_public_key="server-public",
        preshared_key="selected-peer-psk",
        endpoint="vpn.example.com",
        port=51820,
        allowed_ips=("10.0.0.0/24",),
        keepalive=25,
    )


def test_snapshot_fields_are_exact() -> None:
    assert [field.name for field in fields(ServerPeerSnapshot)] == [
        "public_key",
        "preshared_key",
        "allowed_ips",
    ]
    assert [field.name for field in fields(ServerSnapshot)] == [
        "interface_name",
        "mtu",
        "peers",
    ]
    assert [field.name for field in fields(ClientSnapshot)] == [
        "private_key",
        "ip_address",
        "address_prefix_length",
        "dns",
        "mtu",
        "server_public_key",
        "preshared_key",
        "endpoint",
        "port",
        "allowed_ips",
        "keepalive",
    ]


@pytest.mark.parametrize(
    ("snapshot", "field_names"),
    [
        (
            _server_peer(),
            ("public_key", "preshared_key", "allowed_ips"),
        ),
        (
            _server_snapshot(),
            ("interface_name", "mtu", "peers"),
        ),
        (
            _client_snapshot(),
            (
                "private_key",
                "ip_address",
                "address_prefix_length",
                "dns",
                "mtu",
                "server_public_key",
                "preshared_key",
                "endpoint",
                "port",
                "allowed_ips",
                "keepalive",
            ),
        ),
    ],
)
def test_every_snapshot_field_is_frozen(
    snapshot: object,
    field_names: tuple[str, ...],
) -> None:
    for field_name in field_names:
        with pytest.raises(FrozenInstanceError):
            setattr(snapshot, field_name, "changed")


def test_snapshots_use_slots_and_tuple_collections() -> None:
    peer = _server_peer()
    server = _server_snapshot()
    client = _client_snapshot()

    assert not hasattr(peer, "__dict__")
    assert not hasattr(server, "__dict__")
    assert not hasattr(client, "__dict__")
    assert isinstance(peer.allowed_ips, tuple)
    assert isinstance(server.peers, tuple)
    assert isinstance(client.allowed_ips, tuple)


def test_server_snapshot_excludes_unrelated_and_private_fields() -> None:
    field_names = {
        field.name for cls in (ServerPeerSnapshot, ServerSnapshot) for field in fields(cls)
    }

    assert field_names.isdisjoint(
        {
            "private_key",
            "listen_port",
            "server_public_key",
            "endpoint",
            "dns",
            "keepalive",
            "peer_id",
            "node_id",
            "name",
            "description",
            "expires_at",
            "role",
            "routing_policy",
        }
    )


def test_client_snapshot_contains_only_selected_target_values() -> None:
    field_names = {field.name for field in fields(ClientSnapshot)}

    assert "private_key" in field_names
    assert "preshared_key" in field_names
    assert field_names.isdisjoint(
        {
            "server_private_key",
            "peer_id",
            "node_id",
            "description",
            "audit_events",
            "expires_at",
            "role",
            "routing_policy",
            "routed_networks",
            "peers",
        }
    )
