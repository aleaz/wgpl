import datetime

import pytest

from wgpl import core, db, wireguard
from wgpl.core import _get_next_available_ip, resolve_peer_ref
from wgpl.exceptions import AmbiguousPeerIdError, PeerNotFoundError


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


def _insert_peer(
    peer_id: str,
    interface: str,
    name: str,
    ip_address: str,
) -> None:
    keypair = wireguard.generate_keypair()
    db.add_peer(
        id=peer_id,
        interface=interface,
        name=name,
        ip_address=ip_address,
        public_key=keypair.public_key,
        private_key=keypair.private_key,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def test_resolve_peer_ref_full_uuid_with_hyphens(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    assert resolve_peer_ref(peer_id) == peer_id


def test_resolve_peer_ref_full_uuid_without_hyphens(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    assert resolve_peer_ref("55c521ad2d9446898abc123456789abc") == peer_id


def test_resolve_peer_ref_unique_prefix(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    assert resolve_peer_ref("55c521ad2d94") == peer_id


def test_resolve_peer_ref_ambiguous_prefix(wg0_interface: str) -> None:
    _insert_peer("55c521ad-2d94-4689-8abc-111111111111", wg0_interface, "phone", "10.0.0.2")
    _insert_peer("55c521ff-8abc-4689-8abc-222222222222", wg0_interface, "laptop", "10.0.0.3")

    with pytest.raises(AmbiguousPeerIdError, match="ambiguous"):
        resolve_peer_ref("55c521")


def test_resolve_peer_ref_not_found(wg0_interface: str) -> None:
    with pytest.raises(PeerNotFoundError):
        resolve_peer_ref("deadbeefcafe")


def test_resolve_peer_ref_prefix_too_short(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    with pytest.raises(PeerNotFoundError):
        resolve_peer_ref("55c")


def test_resolve_peer_ref_scoped_to_interface(wg0_interface: str, wgpl_db: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    public_key = wireguard.generate_keypair().public_key
    db.add_interface("wg1", "vpn2.example.com", public_key, "10.0.1.0/24", 51821)

    assert resolve_peer_ref("55c521ad2d94", wg0_interface) == peer_id

    with pytest.raises(PeerNotFoundError):
        resolve_peer_ref("55c521ad2d94", "wg1")


def test_remove_peer_with_prefix(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    core.remove_peer(wg0_interface, "55c521ad2d94")

    assert db.get_peer(peer_id) is None


def test_get_peer_qr_png_bytes_returns_valid_png(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "qr_peer")
    png_bytes = core.get_peer_qr_png_bytes(result["id"])

    assert png_bytes.startswith(b"\x89PNG")
    assert len(png_bytes) > 100
