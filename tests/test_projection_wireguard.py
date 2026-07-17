"""Stage 3 tests for the WireGuard renderer and static composition."""

from __future__ import annotations

import inspect
from unittest.mock import MagicMock, patch

import pytest

from wgpl.exceptions import ProjectionRenderError, WgplException
from wgpl.projection import composition
from wgpl.projection.snapshots import (
    ClientSnapshot,
    ServerPeerSnapshot,
    ServerSnapshot,
)
from wgpl.projection.wireguard import WireGuardProjection


CLIENT_PRIVATE_KEY = "client-private-secret"
CLIENT_PSK = "client-preshared-secret"


def _exception_messages(error: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        messages.append(str(current))
        current = current.__cause__ or current.__context__
    return tuple(messages)


def _server_snapshot() -> ServerSnapshot:
    return ServerSnapshot(
        interface_name="wg0",
        mtu=1420,
        peers=(
            ServerPeerSnapshot(
                public_key="peer-10-public",
                preshared_key="peer-10-psk",
                allowed_ips=("10.0.0.10/32", "192.168.10.0/24"),
            ),
            ServerPeerSnapshot(
                public_key="peer-2-public",
                preshared_key=None,
                allowed_ips=("10.0.0.2/32",),
            ),
        ),
    )


def _client_snapshot() -> ClientSnapshot:
    return ClientSnapshot(
        private_key=CLIENT_PRIVATE_KEY,
        ip_address="10.0.0.2",
        address_prefix_length=24,
        dns="1.1.1.1, 1.0.0.1",
        mtu=1380,
        server_public_key="server-public",
        preshared_key=CLIENT_PSK,
        endpoint="vpn.example.com",
        port=51820,
        allowed_ips=("10.0.0.0/24", "10.50.0.0/16"),
        keepalive=25,
    )


def test_wireguard_identifier_is_exact() -> None:
    assert WireGuardProjection.identifier == "wireguard"


@patch("wgpl.projection.wireguard.wireformat.build_server_config")
def test_server_adapter_passes_exact_formatter_shape(
    build_server: MagicMock,
) -> None:
    build_server.return_value = "server-artifact"
    snapshot = _server_snapshot()

    result = WireGuardProjection().render_server(snapshot)

    assert result == "server-artifact"
    build_server.assert_called_once_with(
        {"name": "wg0", "mtu": 1420},
        [
            (
                {
                    "public_key": "peer-10-public",
                    "preshared_key": "peer-10-psk",
                },
                ["10.0.0.10/32", "192.168.10.0/24"],
            ),
            (
                {
                    "public_key": "peer-2-public",
                    "preshared_key": None,
                },
                ["10.0.0.2/32"],
            ),
        ],
    )


@patch("wgpl.projection.wireguard.wireformat.build_client_config")
def test_client_adapter_passes_exact_formatter_shape(
    build_client: MagicMock,
) -> None:
    build_client.return_value = "client-artifact"

    result = WireGuardProjection().render_client(_client_snapshot())

    assert result == "client-artifact"
    build_client.assert_called_once_with(
        {
            "private_key": CLIENT_PRIVATE_KEY,
            "ip_address": "10.0.0.2",
            "preshared_key": CLIENT_PSK,
            "dns": "1.1.1.1, 1.0.0.1",
            "mtu": 1380,
            "keepalive": 25,
        },
        {
            "address_pool": "0.0.0.0/24",
            "endpoint": "vpn.example.com",
            "port": 51820,
            "public_key": "server-public",
            "dns": None,
            "mtu": None,
            "keepalive": None,
        },
        "10.0.0.0/24,10.50.0.0/16",
    )


@patch("wgpl.projection.wireguard.wireformat.build_server_config")
def test_renderer_creates_fresh_adapter_mappings(
    build_server: MagicMock,
) -> None:
    build_server.return_value = "artifact"
    renderer = WireGuardProjection()
    snapshot = _server_snapshot()

    renderer.render_server(snapshot)
    first_interface, first_peers = build_server.call_args.args
    first_interface["name"] = "mutated"
    first_peers[0][0]["public_key"] = "mutated"
    first_peers[0][1].append("203.0.113.0/24")
    renderer.render_server(snapshot)
    second_interface, second_peers = build_server.call_args.args

    assert second_interface == {"name": "wg0", "mtu": 1420}
    assert second_peers[0] == (
        {
            "public_key": "peer-10-public",
            "preshared_key": "peer-10-psk",
        },
        ["10.0.0.10/32", "192.168.10.0/24"],
    )
    assert vars(renderer) == {}


def test_renderer_performs_no_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_io(*args: object, **kwargs: object) -> None:
        raise AssertionError("renderer attempted I/O")

    monkeypatch.setattr("builtins.open", fail_io)
    monkeypatch.setattr("sqlite3.connect", fail_io)
    monkeypatch.setattr("socket.socket", fail_io)
    monkeypatch.setattr("subprocess.run", fail_io)
    renderer = WireGuardProjection()

    assert renderer.render_server(ServerSnapshot("wg0", None, ())) == ""
    assert "[Interface]" in renderer.render_client(_client_snapshot())


def test_sparse_snapshots_have_exact_repeatable_utf8_bytes() -> None:
    renderer = WireGuardProjection()
    server = ServerSnapshot(
        interface_name="wg0",
        mtu=None,
        peers=(
            ServerPeerSnapshot(
                public_key="peer-public",
                preshared_key=None,
                allowed_ips=("10.0.0.2/32",),
            ),
        ),
    )
    client = ClientSnapshot(
        private_key="client-private",
        ip_address="10.0.0.2",
        address_prefix_length=24,
        dns=None,
        mtu=None,
        server_public_key="server-public",
        preshared_key=None,
        endpoint="vpn.example.com",
        port=51820,
        allowed_ips=("10.0.0.0/24",),
        keepalive=None,
    )
    expected_server = (
        b"[Peer]\n"
        b"PublicKey = peer-public\n"
        b"AllowedIPs = 10.0.0.2/32\n"
    )
    expected_client = (
        b"[Interface]\n"
        b"PrivateKey = client-private\n"
        b"Address = 10.0.0.2/24\n"
        b"\n"
        b"[Peer]\n"
        b"PublicKey = server-public\n"
        b"Endpoint = vpn.example.com:51820\n"
        b"AllowedIPs = 10.0.0.0/24\n"
    )

    assert renderer.render_server(server).encode("utf-8") == expected_server
    assert renderer.render_server(server).encode("utf-8") == expected_server
    assert renderer.render_client(client).encode("utf-8") == expected_client
    assert renderer.render_client(client).encode("utf-8") == expected_client


def test_static_composition_registry_identity() -> None:
    assert composition._WIREGUARD_ID == "wireguard"
    assert composition._WIREGUARD.identifier == composition._WIREGUARD_ID
    assert composition._ENGINE._projections == {
        "wireguard": composition._WIREGUARD
    }


def test_composition_helpers_dispatch_exact_snapshot_identity() -> None:
    server = _server_snapshot()
    client = _client_snapshot()
    with (
        patch.object(
            composition._ENGINE,
            "render_server",
            return_value="server",
        ) as render_server,
        patch.object(
            composition._ENGINE,
            "render_client",
            return_value="client",
        ) as render_client,
    ):
        assert composition.render_wireguard_server(server) == "server"
        assert composition.render_wireguard_client(client) == "client"

    render_server.assert_called_once_with("wireguard", server)
    render_client.assert_called_once_with("wireguard", client)


def test_composition_exposes_only_target_specific_callable_api() -> None:
    public_functions = {
        name
        for name, value in vars(composition).items()
        if not name.startswith("_")
        and inspect.isfunction(value)
        and value.__module__ == composition.__name__
    }

    assert public_functions == {
        "render_wireguard_client",
        "render_wireguard_server",
    }
    assert not hasattr(composition, "register")
    assert not hasattr(composition, "get_registry")
    assert not hasattr(composition, "render")


def test_composition_preserves_wgpl_exception_identity() -> None:
    error = WgplException("formatter rejected value")
    with patch(
        "wgpl.projection.wireguard.wireformat.build_server_config",
        side_effect=error,
    ):
        with pytest.raises(WgplException) as exc_info:
            composition.render_wireguard_server(_server_snapshot())

    assert exc_info.value is error


def test_composition_wraps_unexpected_error_without_secrets() -> None:
    def fail_after_client_inspection(
        peer: dict[str, object],
        iface: dict[str, object],
        allowed_ips: str,
    ) -> str:
        assert peer["private_key"] == CLIENT_PRIVATE_KEY
        assert peer["preshared_key"] == CLIENT_PSK
        assert iface["public_key"] == "server-public"
        assert allowed_ips == "10.0.0.0/24,10.50.0.0/16"
        try:
            raise LookupError("formatter internals failed")
        except LookupError:
            raise RuntimeError("formatter failed")

    with patch(
        "wgpl.projection.wireguard.wireformat.build_client_config",
        side_effect=fail_after_client_inspection,
    ):
        with pytest.raises(ProjectionRenderError) as exc_info:
            composition.render_wireguard_client(_client_snapshot())

    assert str(exc_info.value) == (
        "Projection 'wireguard' failed for client target"
    )
    chain_messages = _exception_messages(exc_info.value)
    assert chain_messages == (
        "Projection 'wireguard' failed for client target",
        "formatter failed",
        "formatter internals failed",
    )
    for secret in (CLIENT_PRIVATE_KEY, CLIENT_PSK):
        assert all(secret not in message for message in chain_messages)


def test_server_composition_failure_chain_excludes_inspected_secrets() -> None:
    def fail_after_server_inspection(
        iface: dict[str, object],
        peers: list[tuple[dict[str, object], list[str]]],
    ) -> str:
        assert iface["name"] == "wg0"
        assert peers[0][0]["preshared_key"] == "peer-10-psk"
        try:
            raise LookupError("formatter internals failed")
        except LookupError:
            raise RuntimeError("formatter failed")

    with patch(
        "wgpl.projection.wireguard.wireformat.build_server_config",
        side_effect=fail_after_server_inspection,
    ):
        with pytest.raises(ProjectionRenderError) as exc_info:
            composition.render_wireguard_server(_server_snapshot())

    messages = _exception_messages(exc_info.value)
    assert messages == (
        "Projection 'wireguard' failed for server target",
        "formatter failed",
        "formatter internals failed",
    )
    assert all("peer-10-psk" not in message for message in messages)
