"""Stage 2 tests for consistent, least-privilege snapshot assembly."""

from __future__ import annotations

import dataclasses
import datetime
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from wgpl import core, db, integrity, routing
from wgpl.exceptions import WgplException
from wgpl.projection.snapshots import ClientSnapshot, ServerSnapshot

from tests.test_projection_parity import (
    LegacyProjectionState,
    PEER_2_ID,
    PEER_2_PRIVATE_KEY,
    PEER_2_PSK,
    PEER_10_PRIVATE_KEY,
    PEER_10_PSK,
    seed_legacy_projection,
)


@pytest.fixture
def projection_state(wgpl_db: str) -> LegacyProjectionState:
    return seed_legacy_projection()


def _assert_plain_snapshot_value(value: object) -> None:
    assert not isinstance(value, (sqlite3.Row, sqlite3.Connection, Mapping))
    assert not callable(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        for field in dataclasses.fields(value):
            _assert_plain_snapshot_value(getattr(value, field.name))
    elif isinstance(value, tuple):
        for item in value:
            _assert_plain_snapshot_value(item)


def test_read_snapshot_rolls_back_and_closes_connection(
    projection_state: LegacyProjectionState,
) -> None:
    original = db.get_interfaces_by_name("wg0")[0]["mtu"]

    with db.read_snapshot() as conn:
        conn.execute("UPDATE interfaces SET mtu = 1300 WHERE name = 'wg0'")
        changed = conn.execute(
            "SELECT mtu FROM interfaces WHERE name = 'wg0'"
        ).fetchone()
        assert changed is not None
        assert changed["mtu"] == 1300

    assert db.get_interfaces_by_name("wg0")[0]["mtu"] == original
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        conn.execute("SELECT 1")


def test_read_snapshot_rolls_back_on_exception(
    projection_state: LegacyProjectionState,
) -> None:
    original = db.get_interfaces_by_name("wg0")[0]["mtu"]

    with pytest.raises(RuntimeError, match="assembly failed"):
        with db.read_snapshot() as conn:
            conn.execute("UPDATE interfaces SET mtu = 1300 WHERE name = 'wg0'")
            raise RuntimeError("assembly failed")

    assert db.get_interfaces_by_name("wg0")[0]["mtu"] == original


def test_read_snapshot_honors_force_readonly_without_creating_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing_path = tmp_path / "missing.db"
    monkeypatch.setenv("WGPL_DB_PATH", str(missing_path))

    with core.force_readonly(), pytest.raises(
        WgplException,
        match=f"^Database does not exist: {missing_path}$",
    ):
        with db.read_snapshot():
            pass

    assert not missing_path.exists()


def test_builders_use_only_the_supplied_connection(
    projection_state: LegacyProjectionState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_connection() -> Any:
        raise AssertionError("snapshot assembly opened an implicit connection")

    with db.read_snapshot() as conn:
        monkeypatch.setattr(db, "get_db", unexpected_connection)
        server = core._build_server_snapshot("wg0", conn=conn)
        client, _, _ = core._build_client_snapshot(
            PEER_2_ID,
            None,
            interface_ref="wg0",
            conn=conn,
        )

    assert server.interface_name == "wg0"
    assert client.ip_address == "10.0.0.2"


def test_server_projection_renders_after_one_snapshot_connection_closes(
    projection_state: LegacyProjectionState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read_snapshot = db.read_snapshot
    captured: dict[str, sqlite3.Connection] = {}
    snapshot_calls = 0

    @contextmanager
    def tracked_read_snapshot() -> Iterator[sqlite3.Connection]:
        nonlocal snapshot_calls
        snapshot_calls += 1
        with original_read_snapshot() as conn:
            captured["conn"] = conn
            yield conn

    def render_after_close(snapshot: ServerSnapshot) -> str:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            captured["conn"].execute("SELECT 1")
        assert snapshot.interface_name == "wg0"
        return "rendered-after-close"

    monkeypatch.setattr(db, "read_snapshot", tracked_read_snapshot)
    monkeypatch.setattr(core, "render_wireguard_server", render_after_close)

    name, artifact = core._project_server_config("wg0")

    assert snapshot_calls == 1
    assert name == "wg0"
    assert artifact == "rendered-after-close"


def test_client_projection_renders_after_one_snapshot_connection_closes(
    projection_state: LegacyProjectionState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read_snapshot = db.read_snapshot
    captured: dict[str, sqlite3.Connection] = {}
    snapshot_calls = 0

    @contextmanager
    def tracked_read_snapshot() -> Iterator[sqlite3.Connection]:
        nonlocal snapshot_calls
        snapshot_calls += 1
        with original_read_snapshot() as conn:
            captured["conn"] = conn
            yield conn

    def render_after_close(snapshot: ClientSnapshot) -> str:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            captured["conn"].execute("SELECT 1")
        assert snapshot.private_key == PEER_2_PRIVATE_KEY
        assert snapshot.allowed_ips == (
            "10.0.0.0/24",
            "10.50.0.0/16",
            "192.168.10.0/24",
        )
        return "rendered-client-after-close"

    monkeypatch.setattr(db, "read_snapshot", tracked_read_snapshot)
    monkeypatch.setattr(core, "render_wireguard_client", render_after_close)

    artifact, public_allowed_ips, source = core._project_client_config(
        PEER_2_ID,
        None,
        interface_ref="wg0",
    )

    assert snapshot_calls == 1
    assert artifact == "rendered-client-after-close"
    assert public_allowed_ips == (
        "10.0.0.0/24",
        "10.50.0.0/16",
        "192.168.10.0/24",
    )
    assert source == "derived"


def test_server_snapshot_is_ordered_active_and_least_privilege(
    projection_state: LegacyProjectionState,
) -> None:
    with db.read_snapshot() as conn:
        snapshot = core._build_server_snapshot("wg0", conn=conn)

    assert isinstance(snapshot, ServerSnapshot)
    assert snapshot.interface_name == "wg0"
    assert snapshot.mtu == 1420
    assert [peer.allowed_ips[0] for peer in snapshot.peers] == [
        "10.0.0.10/32",
        "10.0.0.2/32",
    ]
    assert PEER_2_PRIVATE_KEY not in repr(snapshot)
    assert PEER_10_PRIVATE_KEY not in repr(snapshot)
    _assert_plain_snapshot_value(snapshot)


def test_server_snapshot_excludes_inactive_peer(
    projection_state: LegacyProjectionState,
) -> None:
    core.remove_peer("wg0", PEER_2_ID)

    with db.read_snapshot() as conn:
        snapshot = core._build_server_snapshot("wg0", conn=conn)

    assert len(snapshot.peers) == 1
    assert snapshot.peers[0].preshared_key == PEER_10_PSK
    assert PEER_2_PSK not in repr(snapshot)


def test_server_snapshot_excludes_expired_peer(
    projection_state: LegacyProjectionState,
) -> None:
    expired_at = datetime.datetime(
        2020,
        1,
        1,
        tzinfo=datetime.timezone.utc,
    ).isoformat()
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?",
            (expired_at, PEER_2_ID),
        )
        conn.commit()

    with db.read_snapshot() as conn:
        snapshot = core._build_server_snapshot("wg0", conn=conn)

    assert len(snapshot.peers) == 1
    assert snapshot.peers[0].preshared_key == PEER_10_PSK
    assert PEER_2_PSK not in repr(snapshot)


@pytest.mark.parametrize(
    ("policy", "custom_allowed_ips", "expected"),
    [
        ("vpn_only", None, ("10.0.0.0/24",)),
        ("split_tunnel", None, ("10.0.0.0/24", "10.50.0.0/16")),
        (
            "all_remote_networks",
            None,
            ("10.0.0.0/24", "10.50.0.0/16", "192.168.10.0/24"),
        ),
        ("full_tunnel", None, ("0.0.0.0/0",)),
        ("custom", "172.16.1.1/16,172.16.0.0/24", ("172.16.0.0/16",)),
    ],
)
def test_client_builder_matches_routing_policy_results(
    projection_state: LegacyProjectionState,
    policy: str,
    custom_allowed_ips: str | None,
    expected: tuple[str, ...],
) -> None:
    with db.get_db() as conn:
        conn.execute(
            """
            UPDATE peers
            SET allowed_ips_policy = ?, custom_allowed_ips = ?
            WHERE id = ?
            """,
            (policy, custom_allowed_ips, PEER_2_ID),
        )
        conn.commit()

    with db.read_snapshot() as conn:
        snapshot, public_allowed_ips, source = core._build_client_snapshot(
            PEER_2_ID,
            None,
            interface_ref="wg0",
            conn=conn,
        )
        peer = db.get_peer(PEER_2_ID, conn=conn)
        assert peer is not None
        iface = db.get_interface(peer["interface_id"], conn=conn)
        assert iface is not None
        active_peers = [
            row
            for row in db.list_peers(peer["interface_id"], conn=conn)
            if integrity.is_peer_active(row)
        ]
        oracle = tuple(
            routing.resolve_client_allowed_ips(peer, iface, active_peers)
        )

    assert snapshot.allowed_ips == expected
    assert snapshot.allowed_ips == oracle
    assert public_allowed_ips == expected
    assert source == "derived"


def test_client_snapshot_resolves_effective_values_and_selected_secrets(
    projection_state: LegacyProjectionState,
) -> None:
    with db.read_snapshot() as conn:
        snapshot, _, _ = core._build_client_snapshot(
            PEER_2_ID,
            None,
            interface_ref="wg0",
            conn=conn,
        )

    assert isinstance(snapshot, ClientSnapshot)
    assert snapshot.private_key == PEER_2_PRIVATE_KEY
    assert snapshot.preshared_key == PEER_2_PSK
    assert snapshot.address_prefix_length == 24
    assert snapshot.dns == "9.9.9.9, 149.112.112.112"
    assert snapshot.mtu == 1380
    assert snapshot.keepalive == 15
    assert PEER_10_PRIVATE_KEY not in repr(snapshot)
    assert PEER_10_PSK not in repr(snapshot)
    _assert_plain_snapshot_value(snapshot)


def test_client_override_keeps_public_metadata_but_normalizes_snapshot(
    projection_state: LegacyProjectionState,
) -> None:
    with db.read_snapshot() as conn:
        snapshot, public_allowed_ips, source = core._build_client_snapshot(
            PEER_2_ID,
            " 10.0.0.1/24 ",
            interface_ref="wg0",
            conn=conn,
        )

    assert snapshot.allowed_ips == ("10.0.0.0/24",)
    assert public_allowed_ips == ("10.0.0.1/24",)
    assert source == "override"


def test_client_projection_excludes_inactive_remote_router(
    projection_state: LegacyProjectionState,
) -> None:
    core.remove_peer("wg0", projection_state["peer_10_id"])

    with db.read_snapshot() as conn:
        snapshot, public_allowed_ips, source = core._build_client_snapshot(
            PEER_2_ID,
            None,
            interface_ref="wg0",
            conn=conn,
        )

    assert snapshot.allowed_ips == ("10.0.0.0/24", "10.50.0.0/16")
    assert public_allowed_ips == snapshot.allowed_ips
    assert source == "derived"
    config = core.get_peer_config(PEER_2_ID, interface_ref="wg0")
    assert "AllowedIPs = 10.0.0.0/24,10.50.0.0/16" in config
    assert "192.168.10.0/24" not in config


def test_custom_projection_collapses_redundant_prefixes_end_to_end(
    projection_state: LegacyProjectionState,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            """
            UPDATE peers
            SET allowed_ips_policy = 'custom',
                custom_allowed_ips = '172.16.1.1/16,172.16.0.0/24'
            WHERE id = ?
            """,
            (PEER_2_ID,),
        )
        conn.commit()

    config = core.get_peer_config(PEER_2_ID, interface_ref="wg0")

    assert "AllowedIPs = 172.16.0.0/16" in config
    assert "172.16.0.0/24" not in config
