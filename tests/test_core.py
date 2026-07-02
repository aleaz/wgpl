from wgpl import core
from wgpl.core import _get_next_available_ip
from wgpl import db


def test_add_peer_returns_safe_fields(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "test_peer")

    assert set(result.keys()) == {"id", "name", "ip_address", "public_key"}
    assert "private_key" not in result
    assert "preshared_key" not in result


def test_get_next_available_ip_skips_gateway(wg0_interface: str) -> None:
    with db.transaction() as conn:
        first_ip = _get_next_available_ip(wg0_interface, conn)

    assert first_ip == "10.0.0.2"

    core.add_peer(wg0_interface, "peer_one")

    with db.transaction() as conn:
        second_ip = _get_next_available_ip(wg0_interface, conn)

    assert second_ip == "10.0.0.3"
