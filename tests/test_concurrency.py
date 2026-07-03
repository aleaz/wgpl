"""Concurrent access tests for WGPL SQLite writes."""

from __future__ import annotations

import threading

from wgpl import core


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
