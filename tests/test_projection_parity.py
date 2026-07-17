"""Legacy projection characterization before the Projection Engine cutover."""

from __future__ import annotations

from collections.abc import Callable
import inspect
from pathlib import Path
from typing import TypedDict
from unittest.mock import MagicMock, patch

import pytest

from wgpl import core, db
from wgpl.exceptions import InterfaceNotFoundError, PeerNotFoundError, WgplException
from wgpl.projection.composition import (
    render_wireguard_client,
    render_wireguard_server,
)


GOLDEN_DIR = Path(__file__).parent / "golden" / "projection"
CREATED_AT = "2025-01-01T00:00:00+00:00"
SERVER_PUBLIC_KEY = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk="

PEER_2_ID = "11111111-1111-4111-8111-111111111102"
PEER_2_NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
PEER_2_PRIVATE_KEY = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
PEER_2_PUBLIC_KEY = "zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk="
PEER_2_PSK = "oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaE="

PEER_10_ID = "11111111-1111-4111-8111-111111111110"
PEER_10_NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa10"
PEER_10_PRIVATE_KEY = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
PEER_10_PUBLIC_KEY = "Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI="
PEER_10_PSK = "oqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqI="


class LegacyProjectionState(TypedDict):
    interface_id: str
    peer_2_id: str
    peer_10_id: str


def seed_legacy_projection() -> LegacyProjectionState:
    """Persist deterministic rows without invoking key/UUID generation."""
    with db.transaction() as conn:
        interface_id = db.add_interface(
            "wg0",
            "vpn.example.com",
            SERVER_PUBLIC_KEY,
            "10.0.0.0/24",
            51820,
            dns="1.1.1.1, 1.0.0.1",
            mtu=1420,
            keepalive=25,
            routed_networks="10.50.0.0/16",
            conn=conn,
        )
        db.add_node(
            PEER_2_NODE_ID,
            "site_a",
            CREATED_AT,
            conn=conn,
        )
        db.add_node(
            PEER_10_NODE_ID,
            "site_b",
            CREATED_AT,
            conn=conn,
        )
        db.add_peer(
            PEER_2_ID,
            interface_id,
            PEER_2_NODE_ID,
            "10.0.0.2",
            PEER_2_PUBLIC_KEY,
            PEER_2_PRIVATE_KEY,
            CREATED_AT,
            preshared_key=PEER_2_PSK,
            dns="9.9.9.9, 149.112.112.112",
            mtu=1380,
            keepalive=15,
            role="subnet_router",
            routed_networks="192.168.20.0/24",
            allowed_ips_policy="all_remote_networks",
            conn=conn,
        )
        db.add_peer(
            PEER_10_ID,
            interface_id,
            PEER_10_NODE_ID,
            "10.0.0.10",
            PEER_10_PUBLIC_KEY,
            PEER_10_PRIVATE_KEY,
            CREATED_AT,
            preshared_key=PEER_10_PSK,
            dns="8.8.8.8",
            mtu=1360,
            keepalive=20,
            role="subnet_router",
            routed_networks="192.168.10.0/24",
            allowed_ips_policy="all_remote_networks",
            conn=conn,
        )

    return {
        "interface_id": str(interface_id),
        "peer_2_id": PEER_2_ID,
        "peer_10_id": PEER_10_ID,
    }


def _project_server(interface_ref: str) -> str:
    with db.read_snapshot() as conn:
        snapshot = core._build_server_snapshot(interface_ref, conn=conn)
    return render_wireguard_server(snapshot)


def _project_client(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> str:
    with db.read_snapshot() as conn:
        snapshot, _, _ = core._build_client_snapshot(
            peer_id,
            allowed_ips,
            interface_ref=interface_ref,
            conn=conn,
        )
    return render_wireguard_client(snapshot)


def _expected_client_artifact(allowed_ips: str) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {PEER_2_PRIVATE_KEY}\n"
        "Address = 10.0.0.2/24\n"
        "DNS = 9.9.9.9, 149.112.112.112\n"
        "MTU = 1380\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {SERVER_PUBLIC_KEY}\n"
        f"PresharedKey = {PEER_2_PSK}\n"
        "Endpoint = vpn.example.com:51820\n"
        f"AllowedIPs = {allowed_ips}\n"
        "PersistentKeepalive = 15\n"
    )


@pytest.fixture
def legacy_projection_state(wgpl_db: str) -> LegacyProjectionState:
    """Provide a deterministic legacy projection state."""
    return seed_legacy_projection()


def test_projection_public_function_signatures_are_stable() -> None:
    expected = {
        "get_interface_config": "(interface_ref: str) -> str",
        "sync_interface": "(interface_ref: str) -> None",
        "get_peer_config": (
            "(peer_id: str, allowed_ips: str | None = None, *, "
            "interface_ref: str | None = None) -> str"
        ),
        "get_peer_config_payload": (
            "(peer_id: str, allowed_ips: str | None = None, *, "
            "interface_ref: str | None = None) -> dict[str, typing.Any]"
        ),
        "get_peer_qr": (
            "(peer_id: str, allowed_ips: str | None = None, *, "
            "interface_ref: str | None = None) -> str"
        ),
        "get_peer_qr_png_bytes": (
            "(peer_id: str, allowed_ips: str | None = None, *, "
            "interface_ref: str | None = None) -> bytes"
        ),
    }

    assert {
        name: str(inspect.signature(getattr(core, name))) for name in expected
    } == expected


def test_legacy_server_config_matches_golden_bytes(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    expected = (GOLDEN_DIR / "server.conf").read_bytes()

    legacy = core._emit_server_config("wg0").encode()
    first = core.get_interface_config("wg0").encode()
    second = core.get_interface_config("wg0").encode()
    projected_first = _project_server("wg0").encode()
    projected_second = _project_server("wg0").encode()

    assert legacy == expected
    assert first == expected
    assert second == expected
    assert projected_first == expected
    assert projected_second == expected
    assert expected.endswith(b"\n")


def test_legacy_client_config_matches_golden_bytes(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    expected = (GOLDEN_DIR / "client.conf").read_bytes()

    legacy = core._emit_client_config(
        PEER_2_ID,
        interface_ref="wg0",
    ).encode()
    first = core.get_peer_config(PEER_2_ID, interface_ref="wg0").encode()
    second = core.get_peer_config(PEER_2_ID, interface_ref="wg0").encode()
    projected_first = _project_client(
        PEER_2_ID,
        interface_ref="wg0",
    ).encode()
    projected_second = _project_client(
        PEER_2_ID,
        interface_ref="wg0",
    ).encode()

    assert legacy == expected
    assert first == expected
    assert second == expected
    assert projected_first == expected
    assert projected_second == expected
    assert expected.endswith(b"\n")


@pytest.mark.parametrize(
    ("scenario", "expected_allowed_ips"),
    [
        ("vpn-only", "10.0.0.0/24"),
        ("split-tunnel", "10.0.0.0/24,10.50.0.0/16"),
        (
            "all-remote-networks",
            "10.0.0.0/24,10.50.0.0/16,192.168.10.0/24",
        ),
        ("full-tunnel", "0.0.0.0/0"),
        ("custom", "172.16.0.0/16"),
        ("override", "10.0.0.0/24,192.168.1.0/24"),
        (
            "own-lan-exclusion",
            "10.0.0.0/24,10.50.0.0/16,192.168.10.0/24",
        ),
        (
            "multiple-routed-networks",
            "10.0.0.0/24,10.50.0.0/16,172.16.0.0/16,192.168.10.0/24",
        ),
        ("redundant-prefix-collapse", "172.16.0.0/16"),
        ("inactive-router-exclusion", "10.0.0.0/24,10.50.0.0/16"),
    ],
)
def test_exact_client_routing_artifact_matrix(
    legacy_projection_state: LegacyProjectionState,
    scenario: str,
    expected_allowed_ips: str,
) -> None:
    allowed_ips_override: str | None = None
    with db.get_db() as conn:
        if scenario == "vpn-only":
            conn.execute(
                "UPDATE peers SET allowed_ips_policy = 'vpn_only' WHERE id = ?",
                (PEER_2_ID,),
            )
        elif scenario == "split-tunnel":
            conn.execute(
                "UPDATE peers SET allowed_ips_policy = 'split_tunnel' WHERE id = ?",
                (PEER_2_ID,),
            )
        elif scenario == "full-tunnel":
            conn.execute(
                "UPDATE peers SET allowed_ips_policy = 'full_tunnel' WHERE id = ?",
                (PEER_2_ID,),
            )
        elif scenario in {"custom", "redundant-prefix-collapse"}:
            conn.execute(
                """
                UPDATE peers
                SET allowed_ips_policy = 'custom',
                    custom_allowed_ips = '172.16.1.1/16,172.16.0.0/24'
                WHERE id = ?
                """,
                (PEER_2_ID,),
            )
        elif scenario == "override":
            allowed_ips_override = "10.0.0.1/24,192.168.1.7/24"
        elif scenario == "multiple-routed-networks":
            conn.execute(
                """
                UPDATE peers
                SET routed_networks = '192.168.10.0/24,172.16.0.0/16'
                WHERE id = ?
                """,
                (PEER_10_ID,),
            )
        elif scenario == "inactive-router-exclusion":
            conn.execute(
                "UPDATE peers SET deleted_at = ? WHERE id = ?",
                ("2026-01-01T00:00:00+00:00", PEER_10_ID),
            )
        conn.commit()

    artifact = core.get_peer_config(
        PEER_2_ID,
        allowed_ips=allowed_ips_override,
        interface_ref="wg0",
    )

    assert artifact == _expected_client_artifact(expected_allowed_ips)


def test_exact_server_hub_route_artifacts(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    subnet_router = (GOLDEN_DIR / "server.conf").read_text()
    assert core.get_interface_config("wg0") == subnet_router

    with db.get_db() as conn:
        conn.execute(
            """
            UPDATE peers
            SET role = 'endpoint', routed_networks = NULL
            WHERE id = ?
            """,
            (PEER_2_ID,),
        )
        conn.commit()

    endpoint = (
        "MTU = 1420\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {PEER_10_PUBLIC_KEY}\n"
        f"PresharedKey = {PEER_10_PSK}\n"
        "AllowedIPs = 10.0.0.10/32,192.168.10.0/24\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {PEER_2_PUBLIC_KEY}\n"
        f"PresharedKey = {PEER_2_PSK}\n"
        "AllowedIPs = 10.0.0.2/32\n"
    )

    assert core._emit_server_config("wg0") == endpoint
    assert core.get_interface_config("wg0") == endpoint


def test_legacy_server_peer_order_is_textual(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    config = core.get_interface_config("wg0")

    assert config.index(PEER_10_PUBLIC_KEY) < config.index(PEER_2_PUBLIC_KEY)


def test_legacy_empty_server_config_is_empty_string(wgpl_db: str) -> None:
    db.add_interface(
        "wg-empty",
        "empty.example.com",
        PEER_2_PUBLIC_KEY,
        "10.1.0.0/24",
        51821,
    )

    assert core._emit_server_config("wg-empty") == ""
    assert core.get_interface_config("wg-empty") == ""
    assert _project_server("wg-empty") == ""


def test_legacy_server_corrupt_state_fails_before_emit(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET private_key = ? WHERE id = ?",
            ("invalid-private-key", PEER_10_ID),
        )
        conn.commit()

    with pytest.raises(WgplException) as legacy_exc:
        core._emit_server_config("wg0")
    with pytest.raises(WgplException) as exc_info:
        core.get_interface_config("wg0")

    assert str(exc_info.value) == (
        "Database validation failed: wg0/site_b: invalid_wire_fields — "
        "private_key must be valid Base64"
    )
    with pytest.raises(WgplException) as builder_exc:
        _project_server("wg0")
    assert type(exc_info.value) is type(legacy_exc.value)
    assert str(exc_info.value) == str(legacy_exc.value)
    assert type(builder_exc.value) is type(legacy_exc.value)
    assert str(builder_exc.value) == str(legacy_exc.value)


@pytest.mark.parametrize(
    ("statement", "row_id", "value", "target"),
    [
        (
            "UPDATE peers SET private_key = ? WHERE id = ?",
            PEER_2_ID,
            "not-base64",
            "client",
        ),
        (
            "UPDATE interfaces SET public_key = ? WHERE name = ?",
            "wg0",
            "not-base64",
            "client",
        ),
        (
            "UPDATE peers SET public_key = ? WHERE id = ?",
            PEER_2_ID,
            "not-base64",
            "server",
        ),
        (
            "UPDATE peers SET preshared_key = ? WHERE id = ?",
            PEER_2_ID,
            "not-base64",
            "server",
        ),
        (
            "UPDATE nodes SET name = ? WHERE id = ?",
            PEER_2_NODE_ID,
            "unsafe\nnode",
            "client",
        ),
        (
            "UPDATE interfaces SET endpoint = ? WHERE name = ?",
            "wg0",
            "unsafe\nendpoint",
            "client",
        ),
        (
            "UPDATE peers SET ip_address = ? WHERE id = ?",
            PEER_2_ID,
            "unsafe\nip",
            "client",
        ),
        (
            "UPDATE peers SET dns = ? WHERE id = ?",
            PEER_2_ID,
            "unsafe\ndns",
            "client",
        ),
        (
            """
            UPDATE peers
            SET allowed_ips_policy = 'custom', custom_allowed_ips = ?
            WHERE id = ?
            """,
            PEER_2_ID,
            "unsafe\nallowed",
            "client",
        ),
        (
            "UPDATE interfaces SET port = ? WHERE name = ?",
            "wg0",
            70000,
            "client",
        ),
        (
            "UPDATE interfaces SET address_pool = ? WHERE name = ?",
            "wg0",
            "not-a-pool",
            "client",
        ),
        (
            "UPDATE peers SET mtu = ? WHERE id = ?",
            PEER_2_ID,
            1,
            "client",
        ),
        (
            "UPDATE peers SET keepalive = ? WHERE id = ?",
            PEER_2_ID,
            70000,
            "client",
        ),
        (
            "UPDATE peers SET expires_at = ? WHERE id = ?",
            PEER_2_ID,
            "not-a-timestamp",
            "client",
        ),
        (
            "UPDATE peers SET routed_networks = ? WHERE id = ?",
            PEER_10_ID,
            "not-a-network",
            "server",
        ),
    ],
    ids=[
        "client-private-key",
        "interface-public-key",
        "peer-public-key",
        "preshared-key",
        "wire-safe-name",
        "endpoint",
        "ip-address",
        "dns",
        "allowed-ips",
        "port",
        "address-pool",
        "mtu",
        "keepalive",
        "lifecycle",
        "routing",
    ],
)
@patch("wgpl.core.wireguard.syncconf")
def test_corrupt_state_has_differential_failure_parity_and_blocks_apply(
    mock_syncconf: MagicMock,
    legacy_projection_state: LegacyProjectionState,
    statement: str,
    row_id: str,
    value: object,
    target: str,
) -> None:
    with db.get_db() as conn:
        conn.execute(statement, (value, row_id))
        conn.commit()

    def capture(call: Callable[[], object]) -> tuple[type[BaseException], str]:
        with pytest.raises(WgplException) as exc_info:
            call()
        return type(exc_info.value), str(exc_info.value)

    if target == "server":
        legacy_failure = capture(lambda: core._emit_server_config("wg0"))
        projected_failure = capture(lambda: core.get_interface_config("wg0"))
    else:
        legacy_failure = capture(
            lambda: core._emit_client_config(PEER_2_ID, interface_ref="wg0")
        )
        projected_failure = capture(
            lambda: core.get_peer_config(PEER_2_ID, interface_ref="wg0")
        )

    assert projected_failure == legacy_failure
    capture(lambda: core.sync_interface("wg0"))
    mock_syncconf.assert_not_called()


@pytest.mark.parametrize(
    ("peer_ref", "interface_ref"),
    [
        ("11111111", None),
        (PEER_2_ID, "wg1"),
    ],
    ids=["ambiguous-prefix", "interface-mismatch"],
)
def test_reference_failures_have_exact_legacy_projection_parity(
    legacy_projection_state: LegacyProjectionState,
    peer_ref: str,
    interface_ref: str | None,
) -> None:
    db.add_interface(
        "wg1",
        "vpn-alt.example.com",
        "REREREREREREREREREREREREREREREREREREREREREQ=",
        "10.1.0.0/24",
    )

    def capture(call: Callable[[], object]) -> tuple[type[BaseException], str]:
        with pytest.raises(WgplException) as exc_info:
            call()
        return type(exc_info.value), str(exc_info.value)

    legacy_failure = capture(
        lambda: core._emit_client_config(
            peer_ref,
            interface_ref=interface_ref,
        )
    )
    projected_failure = capture(
        lambda: core.get_peer_config(
            peer_ref,
            interface_ref=interface_ref,
        )
    )

    assert projected_failure == legacy_failure


def test_missing_interface_after_peer_resolution_has_exact_parity(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(
            "UPDATE peers SET interface_id = 999999 WHERE id = ?",
            (PEER_2_ID,),
        )
        conn.commit()

    with pytest.raises(WgplException) as legacy_exc:
        core._emit_client_config(PEER_2_ID)
    with pytest.raises(WgplException) as projected_exc:
        core.get_peer_config(PEER_2_ID)

    assert type(projected_exc.value) is type(legacy_exc.value)
    assert str(projected_exc.value) == str(legacy_exc.value)


def test_missing_server_interface_has_exact_parity(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with pytest.raises(WgplException) as legacy_exc:
        core._emit_server_config("missing")
    with pytest.raises(WgplException) as projected_exc:
        core.get_interface_config("missing")

    assert type(projected_exc.value) is type(legacy_exc.value)
    assert str(projected_exc.value) == str(legacy_exc.value)


def test_invalid_override_has_exact_parity(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with pytest.raises(WgplException) as legacy_exc:
        core._emit_client_config(
            PEER_2_ID,
            allowed_ips="not-a-network",
            interface_ref="wg0",
        )
    with pytest.raises(WgplException) as projected_exc:
        core.get_peer_config(
            PEER_2_ID,
            allowed_ips="not-a-network",
            interface_ref="wg0",
        )

    assert type(projected_exc.value) is type(legacy_exc.value)
    assert str(projected_exc.value) == str(legacy_exc.value)


def test_warning_only_state_preserves_legacy_output(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute("UPDATE interfaces SET keepalive = NULL WHERE name = 'wg0'")
        conn.execute(
            "UPDATE peers SET keepalive = NULL WHERE id = ?",
            (PEER_10_ID,),
        )
        conn.commit()

    legacy = core._emit_server_config("wg0")
    projected = core.get_interface_config("wg0")

    assert projected == legacy


def test_legacy_client_reference_error_precedes_preflight(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET private_key = ? WHERE id = ?",
            ("invalid-private-key", PEER_10_ID),
        )
        conn.commit()

    with pytest.raises(PeerNotFoundError) as legacy_exc:
        core._emit_client_config(
            "00000000-0000-0000-0000-000000000001"
        )
    with pytest.raises(PeerNotFoundError) as exc_info:
        core.get_peer_config("00000000-0000-0000-0000-000000000001")

    assert str(exc_info.value) == (
        "Peer 00000000-0000-0000-0000-000000000001 not found"
    )
    with pytest.raises(PeerNotFoundError) as builder_exc:
        _project_client("00000000-0000-0000-0000-000000000001")
    assert type(exc_info.value) is type(legacy_exc.value)
    assert str(exc_info.value) == str(legacy_exc.value)
    assert type(builder_exc.value) is type(legacy_exc.value)
    assert str(builder_exc.value) == str(legacy_exc.value)


def test_legacy_client_inactive_reference_error_precedes_preflight(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    core.remove_peer("wg0", PEER_2_ID)
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET private_key = ? WHERE id = ?",
            ("invalid-private-key", PEER_10_ID),
        )
        conn.commit()

    with pytest.raises(PeerNotFoundError) as legacy_exc:
        core._emit_client_config(PEER_2_ID, interface_ref="wg0")
    with pytest.raises(PeerNotFoundError) as exc_info:
        core.get_peer_config(PEER_2_ID, interface_ref="wg0")

    assert str(exc_info.value) == f"Peer {PEER_2_ID} not found"
    with pytest.raises(PeerNotFoundError) as builder_exc:
        _project_client(PEER_2_ID, interface_ref="wg0")
    assert type(exc_info.value) is type(legacy_exc.value)
    assert str(exc_info.value) == str(legacy_exc.value)
    assert type(builder_exc.value) is type(legacy_exc.value)
    assert str(builder_exc.value) == str(legacy_exc.value)


def test_legacy_client_preflight_precedes_invalid_override(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET private_key = ? WHERE id = ?",
            ("invalid-private-key", PEER_10_ID),
        )
        conn.commit()

    with pytest.raises(WgplException) as legacy_exc:
        core._emit_client_config(
            PEER_2_ID,
            allowed_ips="not-a-network",
            interface_ref="wg0",
        )
    with pytest.raises(WgplException) as exc_info:
        core.get_peer_config(
            PEER_2_ID,
            allowed_ips="not-a-network",
            interface_ref="wg0",
        )

    assert str(exc_info.value) == (
        "Database validation failed: wg0/site_b: invalid_wire_fields — "
        "private_key must be valid Base64"
    )
    with pytest.raises(WgplException) as builder_exc:
        _project_client(
            PEER_2_ID,
            "not-a-network",
            interface_ref="wg0",
        )
    assert type(exc_info.value) is type(legacy_exc.value)
    assert str(exc_info.value) == str(legacy_exc.value)
    assert type(builder_exc.value) is type(legacy_exc.value)
    assert str(builder_exc.value) == str(legacy_exc.value)


def test_projected_override_matches_legacy_normalization(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    legacy = core._emit_client_config(
        PEER_2_ID,
        allowed_ips="10.0.0.1/24, 192.168.1.7/24",
        interface_ref="wg0",
    )
    projected_first = _project_client(
        PEER_2_ID,
        "10.0.0.1/24, 192.168.1.7/24",
        interface_ref="wg0",
    )
    projected_second = _project_client(
        PEER_2_ID,
        "10.0.0.1/24, 192.168.1.7/24",
        interface_ref="wg0",
    )

    assert projected_first == legacy
    assert projected_second == legacy
    assert "AllowedIPs = 10.0.0.0/24,192.168.1.0/24" in projected_first


def test_stage_5_public_facades_use_target_specific_projection_helpers(
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with (
        patch.object(
            core,
            "_project_server_config",
            return_value=("wg0", "projected-server"),
        ) as project_server,
        patch.object(
            core,
            "_project_client_config",
            return_value=(
                "projected-client",
                ("10.0.0.0/24",),
                "derived",
            ),
        ) as project_client,
    ):
        assert core.get_interface_config("wg0") == "projected-server"
        assert (
            core.get_peer_config(PEER_2_ID, interface_ref="wg0")
            == "projected-client"
        )

    project_server.assert_called_once_with("wg0")
    project_client.assert_called_once_with(
        PEER_2_ID,
        None,
        interface_ref="wg0",
    )


@pytest.mark.parametrize(
    "allowed_ips",
    [None, "10.0.0.1/24, 192.168.1.7/24"],
    ids=["derived", "override"],
)
def test_client_config_and_payload_legacy_rollback_parity(
    legacy_projection_state: LegacyProjectionState,
    allowed_ips: str | None,
) -> None:
    legacy_config = core._emit_client_config(
        PEER_2_ID,
        allowed_ips=allowed_ips,
        interface_ref="wg0",
    )
    legacy_payload = core._get_peer_config_payload_legacy(
        PEER_2_ID,
        allowed_ips=allowed_ips,
        interface_ref="wg0",
    )

    assert core.get_peer_config(
        PEER_2_ID,
        allowed_ips=allowed_ips,
        interface_ref="wg0",
    ) == legacy_config
    assert core.get_peer_config_payload(
        PEER_2_ID,
        allowed_ips=allowed_ips,
        interface_ref="wg0",
    ) == legacy_payload


@patch("wgpl.core.wireguard.syncconf")
def test_legacy_apply_interface_error_precedes_server_preflight(
    mock_syncconf: MagicMock,
    legacy_projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET private_key = ? WHERE id = ?",
            ("invalid-private-key", PEER_10_ID),
        )
        conn.commit()

    with pytest.raises(InterfaceNotFoundError) as exc_info:
        core.sync_interface("missing")

    assert str(exc_info.value) == "Interface missing not found"
    mock_syncconf.assert_not_called()
