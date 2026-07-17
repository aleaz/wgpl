"""Concurrent access tests for WGPL SQLite writes."""

from __future__ import annotations

import sqlite3
import threading

import pytest

from wgpl import core, db, wireguard

from tests.test_projection_parity import (
    PEER_2_ID,
    PEER_2_PRIVATE_KEY,
    PEER_2_PSK,
    seed_legacy_projection,
)


def test_concurrent_add_peer_assigns_unique_ips(wg0_interface: str) -> None:
    worker_count = 15
    errors: list[BaseException] = []
    ips_lock = threading.Lock()
    assigned_ips: list[str] = []

    def worker(index: int) -> None:
        try:
            peer = core.add_peer(wg0_interface, f"peer-{index}")
            with ips_lock:
                assigned_ips.append(str(peer["ip_address"]))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert not errors, errors
    assert len(assigned_ips) == worker_count
    assert len(set(assigned_ips)) == worker_count


def test_projection_builder_never_observes_mixed_committed_state(
    wgpl_db: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_legacy_projection()
    reader_pinned = threading.Event()
    writer_done = threading.Event()
    writer_errors: list[BaseException] = []
    new_psk = wireguard.generate_preshared_key()
    original_preflight = core.assert_database_valid

    def coordinated_preflight(
        interface: str | None = None,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        original_preflight(interface, conn=conn)
        reader_pinned.set()
        if not writer_done.wait(timeout=5):
            raise AssertionError("writer did not commit while reader was paused")

    monkeypatch.setattr(core, "assert_database_valid", coordinated_preflight)

    def writer() -> None:
        try:
            if not reader_pinned.wait(timeout=5):
                raise AssertionError("reader did not establish its snapshot")
            with db.transaction() as conn:
                conn.execute(
                    "UPDATE interfaces SET mtu = ? WHERE name = ?",
                    (1300, "wg0"),
                )
                conn.execute(
                    "UPDATE peers SET preshared_key = ? WHERE id = ?",
                    (new_psk, PEER_2_ID),
                )
        except BaseException as exc:
            writer_errors.append(exc)
        finally:
            writer_done.set()

    writer_thread = threading.Thread(target=writer)
    writer_thread.start()
    with db.read_snapshot() as conn:
        snapshot = core._build_server_snapshot("wg0", conn=conn)
    writer_thread.join(timeout=5)

    assert not writer_thread.is_alive()
    assert not writer_errors, writer_errors
    assert snapshot.mtu == 1420
    assert PEER_2_PSK in {peer.preshared_key for peer in snapshot.peers}
    assert new_psk not in {peer.preshared_key for peer in snapshot.peers}
    assert db.get_interfaces_by_name("wg0")[0]["mtu"] == 1300
    peer = db.get_peer(PEER_2_ID)
    assert peer is not None
    assert peer["preshared_key"] == new_psk


def test_client_projection_never_observes_mixed_committed_state(
    wgpl_db: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_legacy_projection()
    reader_pinned = threading.Event()
    writer_done = threading.Event()
    writer_errors: list[BaseException] = []
    new_private_key = wireguard.generate_keypair().private_key
    original_preflight = core.assert_database_valid

    def coordinated_preflight(
        interface: str | None = None,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        original_preflight(interface, conn=conn)
        reader_pinned.set()
        if not writer_done.wait(timeout=5):
            raise AssertionError("writer did not commit while reader was paused")

    monkeypatch.setattr(core, "assert_database_valid", coordinated_preflight)

    def writer() -> None:
        try:
            if not reader_pinned.wait(timeout=5):
                raise AssertionError("reader did not establish its snapshot")
            with db.transaction() as conn:
                conn.execute(
                    "UPDATE interfaces SET endpoint = ? WHERE name = ?",
                    ("new.example.com", "wg0"),
                )
                conn.execute(
                    "UPDATE peers SET private_key = ? WHERE id = ?",
                    (new_private_key, PEER_2_ID),
                )
        except BaseException as exc:
            writer_errors.append(exc)
        finally:
            writer_done.set()

    writer_thread = threading.Thread(target=writer)
    writer_thread.start()
    with db.read_snapshot() as conn:
        snapshot, _, _ = core._build_client_snapshot(
            PEER_2_ID,
            None,
            interface_ref="wg0",
            conn=conn,
        )
    writer_thread.join(timeout=5)

    assert not writer_thread.is_alive()
    assert not writer_errors, writer_errors
    assert snapshot.endpoint == "vpn.example.com"
    assert snapshot.private_key == PEER_2_PRIVATE_KEY
    assert snapshot.private_key != new_private_key
    assert db.get_interfaces_by_name("wg0")[0]["endpoint"] == "new.example.com"
    peer = db.get_peer(PEER_2_ID)
    assert peer is not None
    assert peer["private_key"] == new_private_key
