"""Tests for wireformat export boundary and apply fail-closed behavior."""

from unittest.mock import MagicMock, patch

import pytest

from wgpl import core, db
from wgpl.exceptions import WgplException


def test_get_interface_config_rejects_malicious_public_key(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET public_key = ? WHERE id = ?",
            ("AAAA\nINJECT", peer_id),
        )
        conn.commit()

    with pytest.raises(WgplException, match="unsafe control characters"):
        core.get_interface_config(wg0_interface)


def test_get_peer_config_rejects_invalid_allowed_ips(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")

    with pytest.raises(WgplException, match="AllowedIPs"):
        core.get_peer_config(peer["id"], allowed_ips="not-a-network")


def test_get_peer_config_rejects_markup_injection_in_allowed_ips(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone")

    with pytest.raises(WgplException, match="unsafe control characters"):
        core.get_peer_config(
            peer["id"],
            allowed_ips="0.0.0.0/0\nPrivateKey = stolen",
        )


@patch("wgpl.core.wireguard.syncconf")
def test_sync_interface_fails_on_invalid_wire_fields(
    mock_syncconf: MagicMock, wg0_interface: str
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET public_key = ? WHERE id = ?",
            ("AAAA\nINJECT", peer_id),
        )
        conn.commit()

    with pytest.raises(WgplException, match="Database validation failed"):
        core.sync_interface(wg0_interface)

    mock_syncconf.assert_not_called()


@patch("wgpl.core.wireguard.syncconf")
def test_sync_interface_succeeds_when_database_valid(
    mock_syncconf: MagicMock, wg0_interface: str
) -> None:
    core.add_peer(wg0_interface, "phone")

    core.sync_interface(wg0_interface)

    mock_syncconf.assert_called_once()


def test_get_interface_config_rejects_invalid_mtu(wg0_interface: str) -> None:
    with db.get_db() as conn:
        conn.execute("UPDATE interfaces SET mtu = ? WHERE name = ?", (0, "wg0"))
        conn.commit()

    with pytest.raises(WgplException, match="mtu must be between"):
        core.get_interface_config(wg0_interface)


def test_sync_interface_fails_on_invalid_mtu(
    wg0_interface: str,
) -> None:
    with db.get_db() as conn:
        conn.execute("UPDATE interfaces SET mtu = ? WHERE name = ?", (99999, "wg0"))
        conn.commit()

    with pytest.raises(WgplException, match="Database validation failed"):
        core.sync_interface(wg0_interface)


def test_get_peer_config_rejects_invalid_keepalive(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")

    with db.get_db() as conn:
        conn.execute("UPDATE peers SET keepalive = ? WHERE id = ?", (-1, peer["id"]))
        conn.commit()

    with pytest.raises(WgplException, match="keepalive must be between"):
        core.get_peer_config(peer["id"])
