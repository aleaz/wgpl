"""Adversarial tests for peer activation integrity gate (Phase A)."""

import datetime

import pytest

from wgpl import core, db
from wgpl.exceptions import InvalidPeerIpError, PeersOutsidePoolError, WgplException


def _expire_peer(peer_id: str, hours_ago: int = 2) -> None:
    past = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(hours=hours_ago)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer_id))
        conn.commit()


def test_pool_shrink_rejects_expired_peer_outside_new_pool(wg0_interface: str) -> None:
    expired = core.add_peer(
        wg0_interface, "victim", ip_address="10.0.0.200", expires="7d"
    )
    _expire_peer(str(expired["id"]))

    with pytest.raises(PeersOutsidePoolError):
        core.update_interface(wg0_interface, address_pool="10.0.0.0/25")


def test_clear_expires_blocked_when_ip_outside_pool(wg0_interface: str) -> None:
    expired = core.add_peer(
        wg0_interface, "victim", ip_address="10.0.0.200", expires="7d"
    )
    peer_id = str(expired["id"])
    _expire_peer(peer_id)

    with db.get_db() as conn:
        conn.execute(
            "UPDATE interfaces SET address_pool = ? WHERE id = ?",
            ("10.0.0.0/25", int(wg0_interface)),
        )
        conn.commit()

    with pytest.raises(InvalidPeerIpError):
        core.update_peer(
            wg0_interface,
            peer_id,
            active_only=False,
            clear_expires=True,
        )


def test_add_peer_rejects_zero_duration(wg0_interface: str) -> None:
    with pytest.raises(WgplException, match="greater than zero"):
        core.add_peer(wg0_interface, "instant", expires="0d")


def test_corrupt_expires_at_peer_is_inactive(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "broken")
    peer_id = str(peer["id"])

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?",
            ("not-a-timestamp", peer_id),
        )
        conn.commit()

    row = db.get_peer(peer_id)
    assert row is not None
    assert core.get_peer_status(row) == "Expired"


def test_validate_state_reports_corrupt_expires_at(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "broken")
    peer_id = str(peer["id"])

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?",
            ("", peer_id),
        )
        conn.commit()

    result = core.validate_state(wg0_interface)
    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(i.get("code") == "corrupt_expires_at" for i in issues)


def test_clear_expires_allowed_when_ip_still_in_pool(wg0_interface: str) -> None:
    expired = core.add_peer(
        wg0_interface, "phone", ip_address="10.0.0.50", expires="7d"
    )
    peer_id = str(expired["id"])
    _expire_peer(peer_id)

    result = core.update_peer(
        wg0_interface,
        peer_id,
        active_only=False,
        clear_expires=True,
    )
    assert result["expires_at"] is None
    row = db.get_peer(peer_id)
    assert row is not None
    assert core.get_peer_status(row) == "Active"


def test_validate_wire_mtu_rejects_out_of_range() -> None:
    from wgpl import integrity
    from wgpl.exceptions import WgplException

    with pytest.raises(WgplException, match="1280"):
        integrity.validate_wire_mtu(100)
    with pytest.raises(WgplException, match="65535"):
        integrity.validate_wire_mtu(99999)
    assert integrity.validate_wire_mtu(1420) == 1420


def test_validate_wire_keepalive_rejects_out_of_range() -> None:
    from wgpl import integrity
    from wgpl.exceptions import WgplException

    with pytest.raises(WgplException, match="between 0 and"):
        integrity.validate_wire_keepalive(-1)
    with pytest.raises(WgplException, match="between 0 and"):
        integrity.validate_wire_keepalive(70000)
    assert integrity.validate_wire_keepalive(0) == 0
    assert integrity.validate_wire_keepalive(25) == 25
