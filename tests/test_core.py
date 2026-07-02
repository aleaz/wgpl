import datetime

import pytest

from wgpl import core, db, wireguard
from wgpl.core import validate_dns, allocate_peer_ip, resolve_peer_ref
from wgpl.exceptions import (
    AmbiguousPeerIdError,
    InvalidDnsError,
    InvalidPeerIpError,
    IpAlreadyInUseError,
    NoUpdateFieldsError,
    PeerAlreadyExistsError,
    PeerNotFoundError,
    PeersOutsidePoolError,
)


def test_add_peer_returns_safe_fields(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "test_peer")

    assert set(result.keys()) == {"id", "name", "ip_address", "public_key", "dns"}
    assert result["dns"] is None
    assert "private_key" not in result
    assert "preshared_key" not in result


def test_allocate_peer_ip_skips_gateway(wg0_interface: str) -> None:
    with db.transaction() as conn:
        first_ip = allocate_peer_ip(wg0_interface, conn)

    assert first_ip == "10.0.0.2"

    core.add_peer(wg0_interface, "peer_one")

    with db.transaction() as conn:
        second_ip = allocate_peer_ip(wg0_interface, conn)

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


def test_allocate_peer_ip_with_requested_ip(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "fixed_ip", ip_address="10.0.0.50")

    assert result["ip_address"] == "10.0.0.50"


def test_allocate_peer_ip_rejects_out_of_pool(wg0_interface: str) -> None:
    with pytest.raises(InvalidPeerIpError):
        core.add_peer(wg0_interface, "bad_ip", ip_address="192.168.1.10")


def test_allocate_peer_ip_rejects_gateway(wg0_interface: str) -> None:
    with pytest.raises(InvalidPeerIpError):
        core.add_peer(wg0_interface, "gateway_ip", ip_address="10.0.0.1")


def test_allocate_peer_ip_rejects_in_use(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "first", ip_address="10.0.0.50")

    with pytest.raises(IpAlreadyInUseError):
        core.add_peer(wg0_interface, "second", ip_address="10.0.0.50")


def test_validate_dns_accepts_list() -> None:
    assert validate_dns("1.1.1.1,8.8.8.8") == "1.1.1.1, 8.8.8.8"


def test_validate_dns_rejects_invalid() -> None:
    with pytest.raises(InvalidDnsError):
        validate_dns("not-an-ip")


def test_get_peer_config_uses_interface_dns(wg0_interface: str) -> None:
    db.add_interface(
        "wg_dns",
        "vpn.example.com",
        wireguard.generate_keypair().public_key,
        "10.0.1.0/24",
        dns="1.1.1.1",
    )
    peer = core.add_peer("wg_dns", "phone")

    config = core.get_peer_config(peer["id"])

    assert "DNS = 1.1.1.1" in config


def test_get_peer_config_peer_dns_overrides_interface(wg0_interface: str) -> None:
    db.add_interface(
        "wg_dns2",
        "vpn.example.com",
        wireguard.generate_keypair().public_key,
        "10.0.2.0/24",
        dns="1.1.1.1",
    )
    peer = core.add_peer("wg_dns2", "kids", dns="9.9.9.9")

    config = core.get_peer_config(peer["id"])

    assert "DNS = 9.9.9.9" in config
    assert "1.1.1.1" not in config


def test_update_interface_endpoint(wg0_interface: str) -> None:
    result = core.update_interface(wg0_interface, endpoint="vpn2.example.com")

    assert result["endpoint"] == "vpn2.example.com"
    assert "re_export_clients" in result["hints"]
    assert db.get_interface(wg0_interface)["endpoint"] == "vpn2.example.com"


def test_update_interface_pool_expand_ok(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "peer_one")

    result = core.update_interface(wg0_interface, address_pool="10.0.0.0/23")

    assert result["address_pool"] == "10.0.0.0/23"


def test_update_interface_pool_shrink_rejects(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "high_host", ip_address="10.0.0.200")

    with pytest.raises(PeersOutsidePoolError):
        core.update_interface(wg0_interface, address_pool="10.0.0.0/25")


def test_update_interface_pool_wrong_subnet_rejects(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "peer_one", ip_address="10.0.0.2")

    with pytest.raises(PeersOutsidePoolError):
        core.update_interface(wg0_interface, address_pool="10.0.1.0/24")


def test_update_interface_no_fields_raises(wg0_interface: str) -> None:
    with pytest.raises(NoUpdateFieldsError):
        core.update_interface(wg0_interface)


def test_update_peer_name(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "old_name")

    result = core.update_peer(wg0_interface, peer["id"], name="new_name")

    assert result["name"] == "new_name"
    assert db.get_peer(peer["id"])["name"] == "new_name"


def test_update_peer_name_conflict(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "taken")
    peer = core.add_peer(wg0_interface, "mine")

    with pytest.raises(PeerAlreadyExistsError):
        core.update_peer(wg0_interface, peer["id"], name="taken")


def test_update_peer_ip(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "mobile", ip_address="10.0.0.2")

    result = core.update_peer(wg0_interface, peer["id"], ip_address="10.0.0.50")

    assert result["ip_address"] == "10.0.0.50"
    assert "apply_server" in result["hints"]
    assert "re_export_client" in result["hints"]


def test_update_peer_ip_same(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "stable", ip_address="10.0.0.2")

    result = core.update_peer(wg0_interface, peer["id"], ip_address="10.0.0.2")

    assert result["ip_address"] == "10.0.0.2"


def test_update_peer_clear_dns(wgpl_db: str) -> None:
    public_key = wireguard.generate_keypair().public_key
    db.add_interface("wg_dns", "vpn.example.com", public_key, "10.0.0.0/24", dns="1.1.1.1")
    peer = core.add_peer("wg_dns", "phone", dns="9.9.9.9")

    result = core.update_peer("wg_dns", peer["id"], clear_dns=True)

    assert result["dns_override"] is None
    assert result["dns"] == "1.1.1.1"


def test_validate_state_ok(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "valid_peer")

    result = core.validate_state()

    assert result == {"status": "ok", "issues": []}


def test_validate_state_detects_bad_ip(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    with db.get_db() as conn:
        conn.execute("UPDATE peers SET ip_address = ? WHERE id = ?", ("10.0.1.50", peer_id))
        conn.commit()

    result = core.validate_state(wg0_interface)

    assert result["status"] == "error"
    assert any(issue["code"] == "ip_outside_pool" for issue in result["issues"])
