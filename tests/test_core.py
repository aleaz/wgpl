import datetime
import sqlite3
import subprocess
import uuid
from unittest.mock import patch

import pytest
from typing import Any

from wgpl import core, db, wireguard
from wgpl.core import (
    PeerAccess,
    validate_dns,
    allocate_peer_ip,
    resolve_peer_ref,
)
from wgpl.exceptions import (
    AmbiguousPeerIdError,
    InterfaceDisambiguationRequiredError,
    InvalidDnsError,
    NodeAlreadyExistsError,
    InvalidPeerIpError,
    IpAlreadyInUseError,
    NoAvailableIpsError,
    NoUpdateFieldsError,
    PeerAlreadyExistsError,
    PeerInterfaceMismatchError,
    PeerNotFoundError,
    PeersOutsidePoolError,
    WireguardConfigError,
)


def test_add_peer_returns_safe_fields(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "test_peer")

    assert set(result.keys()) == {
        "id",
        "name",
        "node",
        "node_id",
        "node_created",
        "ip_address",
        "public_key",
        "dns",
        "desc",
        "mtu",
        "keepalive",
        "role",
        "routed_networks",
        "allowed_ips_policy",
        "custom_allowed_ips",
    }
    assert result["dns"] is None
    assert "private_key" not in result
    assert "preshared_key" not in result


def test_add_peer_rejects_invalid_name(wg0_interface: str) -> None:
    with pytest.raises(ValueError, match="invalid characters"):
        core.add_peer(wg0_interface, "bad name with spaces")


def test_allocate_peer_ip_skips_gateway(wg0_interface: str) -> None:
    with db.transaction() as conn:
        first_ip = allocate_peer_ip(int(wg0_interface), conn)

    assert first_ip == "10.0.0.2"

    core.add_peer(wg0_interface, "peer_one")

    with db.transaction() as conn:
        second_ip = allocate_peer_ip(int(wg0_interface), conn)

    assert second_ip == "10.0.0.3"


def _ensure_node(name: str) -> str:
    existing = db.get_node_by_name(name)
    if existing is not None:
        return str(existing["id"])
    node_id = str(uuid.uuid4())
    db.add_node(node_id, name, datetime.datetime.now(datetime.timezone.utc).isoformat())
    return node_id


def _insert_peer(
    peer_id: str,
    interface: str,
    name: str,
    ip_address: str,
) -> None:
    keypair = wireguard.generate_keypair()
    db.add_peer(
        id=peer_id,
        interface_id=1,
        node_id=_ensure_node(name),
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
    _insert_peer(
        "55c521ad-2d94-4689-8abc-111111111111", wg0_interface, "phone", "10.0.0.2"
    )
    _insert_peer(
        "55c521ff-8abc-4689-8abc-222222222222", wg0_interface, "laptop", "10.0.0.3"
    )

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

    with pytest.raises(PeerInterfaceMismatchError, match="does not belong"):
        resolve_peer_ref("55c521ad2d94", "wg1")


def test_remove_peer_with_prefix(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    canonical_id = core.resolve_peer_ref("55c521ad2d94")
    core.remove_peer(wg0_interface, canonical_id)

    peer = db.get_peer(peer_id)
    assert peer is not None
    assert peer["deleted_at"] is not None


def test_get_peer_qr_png_bytes_returns_valid_png(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "qr_peer")
    assert result["id"] is not None
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


def test_validate_dns_rejects_ipv6() -> None:
    with pytest.raises(InvalidDnsError, match="IPv4 only"):
        validate_dns("2001:db8::1")


def test_get_peer_config_uses_interface_dns(wg0_interface: str) -> None:
    db.add_interface(
        "wg_dns",
        "vpn.example.com",
        wireguard.generate_keypair().public_key,
        "10.0.1.0/24",
        port=51821,
        dns="1.1.1.1",
    )
    peer = core.add_peer("wg_dns", "phone")

    assert peer["id"] is not None
    config = core.get_peer_config(peer["id"], interface_ref="wg_dns")

    assert "DNS = 1.1.1.1" in config


def test_get_peer_config_peer_dns_overrides_interface(wg0_interface: str) -> None:
    db.add_interface(
        "wg_dns2",
        "vpn.example.com",
        wireguard.generate_keypair().public_key,
        "10.0.2.0/24",
        port=51822,
        dns="1.1.1.1",
    )
    peer = core.add_peer("wg_dns2", "kids", dns="9.9.9.9")

    assert peer["id"] is not None
    config = core.get_peer_config(peer["id"], interface_ref="wg_dns2")

    assert "DNS = 9.9.9.9" in config
    assert "1.1.1.1" not in config


def _insert_peer_on_interface(
    peer_id: str,
    interface_id: int,
    name: str,
    ip_address: str,
) -> None:
    keypair = wireguard.generate_keypair()
    db.add_peer(
        id=peer_id,
        interface_id=interface_id,
        node_id=_ensure_node(name),
        ip_address=ip_address,
        public_key=keypair.public_key,
        private_key=keypair.private_key,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def test_get_peer_config_requires_interface_with_multiple_interfaces(
    wgpl_db: str,
) -> None:
    pk1 = wireguard.generate_keypair().public_key
    pk2 = wireguard.generate_keypair().public_key
    iface_a = db.add_interface("wg0", "vpn1.example.com", pk1, "10.0.0.0/24", 51820)
    iface_b = db.add_interface("wg1", "vpn2.example.com", pk2, "10.0.1.0/24", 51821)
    peer_a = "aaaaaaaa-bbbb-cccc-dddd-111111111111"
    peer_b = "bbbbbbbb-bbbb-cccc-dddd-222222222222"
    _insert_peer_on_interface(peer_a, iface_a, "phone", "10.0.0.2")
    _insert_peer_on_interface(peer_b, iface_b, "laptop", "10.0.1.2")

    with pytest.raises(InterfaceDisambiguationRequiredError, match="--interface"):
        core.get_peer_config(peer_a)

    config = core.get_peer_config(peer_a, interface_ref="wg0")
    assert "vpn1.example.com:51820" in config


def test_get_peer_config_interface_ref_disambiguates(wgpl_db: str) -> None:
    pk1 = wireguard.generate_keypair().public_key
    pk2 = wireguard.generate_keypair().public_key
    iface_a = db.add_interface("wg0", "vpn1.example.com", pk1, "10.0.0.0/24", 51820)
    iface_b = db.add_interface("wg1", "vpn2.example.com", pk2, "10.0.1.0/24", 51821)
    peer_a = "55c521ad-2d94-4689-8abc-111111111111"
    peer_b = "55c521ad-ff94-4689-8abc-222222222222"
    _insert_peer_on_interface(peer_a, iface_a, "phone", "10.0.0.2")
    _insert_peer_on_interface(peer_b, iface_b, "laptop", "10.0.1.2")

    with pytest.raises(InterfaceDisambiguationRequiredError, match="--interface"):
        core.get_peer_config("55c521ad")

    config_a = core.get_peer_config("55c521ad", interface_ref="wg0")
    config_b = core.get_peer_config("55c521ad", interface_ref="wg1")

    assert "vpn1.example.com:51820" in config_a
    assert "vpn2.example.com:51821" in config_b


def test_update_interface_endpoint(wg0_interface: str) -> None:
    result = core.update_interface(wg0_interface, endpoint="vpn2.example.com")

    assert result["endpoint"] == "vpn2.example.com"
    hints = result["hints"]
    assert isinstance(hints, list)
    assert "re_export_clients" in hints
    row = db.get_interface(int(wg0_interface))
    assert row is not None
    assert row["endpoint"] == "vpn2.example.com"


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


def test_add_interface_rejects_invalid_mtu(wg0_interface: str) -> None:
    pubkey = wireguard.generate_keypair().public_key
    with pytest.raises(ValueError, match="1280"):
        core.add_interface(
            "wg_mtu",
            "vpn.example.com",
            pubkey,
            "10.0.0.0/24",
            mtu=100,
        )


def test_add_peer_rejects_invalid_keepalive(wg0_interface: str) -> None:
    with pytest.raises(ValueError, match="between 0 and"):
        core.add_peer(wg0_interface, "bad", keepalive=-1)


def test_update_node_name(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "old_name")

    assert peer["id"] is not None
    result = core.update_node("old_name", name="new_name")

    assert result["name"] == "new_name"
    row = db.get_peer(peer["id"])
    assert row is not None
    assert row["name"] == "new_name"


def test_update_node_name_conflict(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "taken")
    core.add_peer(wg0_interface, "mine")

    with pytest.raises(NodeAlreadyExistsError):
        core.update_node("mine", name="taken")


def test_update_peer_ip(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "mobile", ip_address="10.0.0.2")

    assert peer["id"] is not None
    result = core.update_peer(wg0_interface, peer["id"], ip_address="10.0.0.50")

    assert result["ip_address"] == "10.0.0.50"
    hints = result["hints"]
    assert isinstance(hints, list)
    assert "apply_server" in hints
    assert "re_export_client" in hints


def test_update_peer_ip_same(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "stable", ip_address="10.0.0.2")

    assert peer["id"] is not None
    result = core.update_peer(wg0_interface, peer["id"], ip_address="10.0.0.2")

    assert result["ip_address"] == "10.0.0.2"


def test_update_peer_clear_dns(wgpl_db: str) -> None:
    public_key = wireguard.generate_keypair().public_key
    db.add_interface(
        "wg_dns", "vpn.example.com", public_key, "10.0.0.0/24", dns="1.1.1.1"
    )
    peer = core.add_peer("wg_dns", "phone", dns="9.9.9.9")

    assert peer["id"] is not None
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
        conn.execute(
            "UPDATE peers SET ip_address = ? WHERE id = ?", ("10.0.1.50", peer_id)
        )
        conn.commit()

    result = core.validate_state(wg0_interface)

    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(issue["code"] == "ip_outside_pool" for issue in issues)


def test_validate_state_skips_soft_deleted_peer(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")
    core.remove_peer(wg0_interface, peer_id)

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET ip_address = ? WHERE id = ?", ("10.0.1.50", peer_id)
        )
        conn.commit()

    result = core.validate_state(wg0_interface)

    assert result == {"status": "ok", "issues": []}


def test_validate_state_skips_expired_peer(wg0_interface: str) -> None:
    peer_id = "55c521ad-2d94-4689-8abc-123456789abc"
    _insert_peer(peer_id, wg0_interface, "phone", "10.0.0.2")

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET ip_address = ?, expires_at = ? WHERE id = ?",
            ("10.0.1.50", past, peer_id),
        )
        conn.commit()

    result = core.validate_state(wg0_interface)

    assert result == {"status": "ok", "issues": []}


def test_resolve_peer_ref_excludes_soft_deleted_by_default(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    assert peer["id"] is not None
    core.remove_peer(wg0_interface, peer["id"])

    with pytest.raises(PeerNotFoundError):
        resolve_peer_ref(peer["id"])


def test_resolve_peer_ref_includes_soft_deleted_when_mutate(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    assert peer["id"] is not None
    core.remove_peer(wg0_interface, peer["id"])

    assert resolve_peer_ref(peer["id"], access=PeerAccess.MUTATE) == peer["id"]


def test_resolve_peer_ref_excludes_expired_by_default(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", expires="1h")
    assert peer["id"] is not None

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    with pytest.raises(PeerNotFoundError):
        resolve_peer_ref(peer["id"])


def test_expired_peer_releases_ip_for_allocation(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.3", expires="1h")
    assert peer["id"] is not None

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    new_peer = core.add_peer(wg0_interface, "phone2", ip_address="10.0.0.3")
    assert new_peer["ip_address"] == "10.0.0.3"


def test_soft_deleted_peer_releases_ip_for_allocation(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.4")
    assert peer["id"] is not None
    core.remove_peer(wg0_interface, peer["id"])

    new_peer = core.add_peer(wg0_interface, "phone2", ip_address="10.0.0.4")
    assert new_peer["ip_address"] == "10.0.0.4"


def test_expired_peer_releases_name_for_allocation(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.5", expires="1h")
    assert peer["id"] is not None

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    new_peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.6")
    assert new_peer["name"] == "phone"
    assert new_peer["ip_address"] == "10.0.0.6"


def test_prune_removes_expired_peer(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", expires="1h")
    assert peer["id"] is not None

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    assert core.prune_peers(wg0_interface) == 1
    assert db.get_peer(peer["id"]) is None


def test_prune_removes_soft_deleted_peer(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    assert peer["id"] is not None
    core.remove_peer(wg0_interface, peer["id"])

    assert core.prune_peers(wg0_interface) == 1
    assert db.get_peer(peer["id"]) is None


def test_prune_keeps_active_peer(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    assert peer["id"] is not None

    assert core.prune_peers(wg0_interface) == 0
    assert db.get_peer(peer["id"]) is not None


def test_get_peer_status_and_effective_dns(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", dns="1.1.1.1")
    db_peer = db.get_peer(str(peer["id"]))
    assert db_peer is not None
    assert core.get_peer_status(db_peer) == "Active"
    assert core.get_effective_dns(peer["dns"], "8.8.8.8") == "1.1.1.1"
    assert core.get_effective_dns(None, "8.8.8.8") == "8.8.8.8"
    assert core.get_effective_dns(None, None) is None


def test_remove_peer_hard_finds_soft_deleted_peer(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    assert peer["id"] is not None
    core.remove_peer(wg0_interface, peer["id"])

    core.remove_peer(wg0_interface, peer["id"], hard=True)

    assert db.get_peer(peer["id"]) is None


def test_remove_peer_interface_mismatch_raises_domain_error(
    wg0_interface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    monkeypatch.setattr(
        core,
        "resolve_peer_ref",
        lambda ref, iface=None, access=None, policy=None, conn=None: peer["id"],
    )

    assert peer["id"] is not None
    with pytest.raises(PeerInterfaceMismatchError, match="does not belong"):
        valid_key = "a" * 43 + "="
        core.add_interface("wg1", "1.1.1.1", valid_key, "10.1.0.0/24")
        core.remove_peer("wg1", peer["id"])


def test_update_peer_interface_mismatch_raises_domain_error(
    wg0_interface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    monkeypatch.setattr(
        core,
        "resolve_peer_ref",
        lambda ref, iface=None, access=None, policy=None, conn=None: peer["id"],
    )

    assert peer["id"] is not None
    with pytest.raises(PeerInterfaceMismatchError, match="does not belong"):
        valid_key = "a" * 43 + "="
        core.add_interface("wg1", "1.1.1.1", valid_key, "10.1.0.0/24")
        core.update_peer("wg1", peer["id"], desc="renamed")


def test_db_add_peer_duplicate_ip_raises_ip_error(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "first", ip_address="10.0.0.2")
    keypair = wireguard.generate_keypair()

    with pytest.raises(IpAlreadyInUseError, match="10.0.0.2"):
        db.add_peer(
            id=str(uuid.uuid4()),
            interface_id=1,
            node_id=_ensure_node("second"),
            ip_address="10.0.0.2",
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )


def test_db_add_peer_duplicate_name_raises_name_error(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "taken", ip_address="10.0.0.2")
    keypair = wireguard.generate_keypair()

    with pytest.raises(PeerAlreadyExistsError):
        db.add_peer(
            id=str(uuid.uuid4()),
            interface_id=1,
            node_id=_ensure_node("taken"),
            ip_address="10.0.0.3",
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )


def test_get_interface_config_excludes_removed_peer(wg0_interface: str) -> None:
    kept = core.add_peer(wg0_interface, "keep")
    removed = core.add_peer(wg0_interface, "gone")
    assert removed["id"] is not None
    core.remove_peer(wg0_interface, removed["id"])

    config = core.get_interface_config(wg0_interface)

    assert str(kept["public_key"]) in config
    assert str(removed["public_key"]) not in config


def test_add_interface_registers_row(wgpl_db: str) -> None:
    pubkey = wireguard.generate_keypair().public_key
    result = core.add_interface(
        "wg0", "vpn.example.com", pubkey, "10.0.0.0/24", dns="1.1.1.1"
    )

    assert result["address_pool"] == "10.0.0.0/24"
    assert result["dns"] == "1.1.1.1"
    assert db.get_interfaces_by_name("wg0")[0] is not None


def test_remove_interface_deletes_peers(wg0_interface: str) -> None:
    _insert_peer("p1", wg0_interface, "p1", "10.0.0.2")
    core.remove_interface(wg0_interface, force=True)
    result = core.validate_state()
    issues = result["issues"]
    assert isinstance(issues, list)
    assert len(issues) == 0


def test_allocate_peer_ip_raises_when_pool_exhausted(wgpl_db: str) -> None:
    pubkey = wireguard.generate_keypair().public_key
    db.add_interface("wg_tiny", "vpn.example.com", pubkey, "10.0.0.0/30", 51825)
    core.add_peer("wg_tiny", "only")

    with db.transaction() as conn:
        with pytest.raises(NoAvailableIpsError, match="No available IPs"):
            db.add_interface(
                "wg_tiny", "1.1.1.1", "a" * 43 + "=", "10.0.0.0/31", conn=conn
            )
            iface = db.get_interfaces_by_name("wg_tiny", conn)[0]
            core.allocate_peer_ip(iface["id"], conn)


@patch("wgpl.wireguard._assert_wg_bin_unchanged")
@patch("wgpl.wireguard._get_wg_bin", return_value="/usr/bin/wg")
@patch("wgpl.wireguard.subprocess.run")
def test_syncconf_raises_wireguard_config_error(
    mock_run: Any, _mock_wg_bin: Any, _mock_assert: Any
) -> None:
    mock_run.side_effect = subprocess.CalledProcessError(
        1, ["wg", "syncconf"], stderr="invalid configuration"
    )

    with pytest.raises(WireguardConfigError, match="wg command failed"):
        wireguard.syncconf("wg0", "[Interface]\n")


def test_naive_expires_at_does_not_crash_status(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.3")
    naive_future = "2099-01-01 00:00:00"
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?", (naive_future, peer["id"])
        )
        conn.commit()

    row = db.get_peer(str(peer["id"]))
    assert row is not None
    assert core.get_peer_status(row) == "Active"


def test_naive_expires_at_past_is_expired(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.4")
    naive_past = "2020-01-01 00:00:00"
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?", (naive_past, peer["id"])
        )
        conn.commit()

    row = db.get_peer(str(peer["id"]))
    assert row is not None
    assert core.get_peer_status(row) == "Expired"


def test_validate_state_detects_duplicate_active_ip(wg0_interface: str) -> None:
    _insert_peer("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", wg0_interface, "a", "10.0.0.2")
    node_b = _ensure_node("b")
    with db.get_db() as conn:
        conn.execute("DROP INDEX IF EXISTS idx_peers_active_ip")
        conn.execute(
            "INSERT INTO peers (id, interface_id, node_id, ip_address, public_key, private_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                wg0_interface,
                node_b,
                "10.0.0.2",
                "pub2",
                "priv2",
                "2020-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
        result = core.validate_state(wg0_interface, conn=conn)

    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    codes = {issue["code"] for issue in issues}
    assert "duplicate_ip" in codes


def test_soft_delete_uses_iso_utc_timestamp(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    core.remove_peer(wg0_interface, str(peer["id"]))

    row = db.get_peer(str(peer["id"]))
    assert row is not None
    assert row["deleted_at"] is not None
    parsed = datetime.datetime.fromisoformat(str(row["deleted_at"]))
    assert parsed.tzinfo is not None


def test_update_peer_resolve_uses_transaction_connection(
    wg0_interface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    seen_conn: list[sqlite3.Connection | None] = []
    original = core.resolve_peer_ref

    def tracking_resolve(
        ref: str,
        interface: str | None = None,
        *,
        access: PeerAccess = PeerAccess.READ_PUBLIC,
        conn: sqlite3.Connection | None = None,
    ) -> str:
        seen_conn.append(conn)
        return original(ref, interface, access=access, conn=conn)

    monkeypatch.setattr(core, "resolve_peer_ref", tracking_resolve)
    core.update_peer(wg0_interface, str(peer["id"]), dns="9.9.9.9")

    assert seen_conn == [seen_conn[0]]
    assert seen_conn[0] is not None


def test_update_peer_role_endpoint_clears_routed_networks(wg0_interface: str) -> None:
    peer = core.add_peer(
        wg0_interface,
        "site",
        role="subnet_router",
        routed_networks="192.168.1.0/24",
        keepalive=25,
    )
    assert peer["routed_networks"] == "192.168.1.0/24"
    updated = core.update_peer(wg0_interface, str(peer["id"]), role="endpoint")
    assert updated["role"] == "endpoint"
    assert updated["routed_networks"] is None


def test_update_peer_non_custom_policy_clears_custom_allowed_ips(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(
        wg0_interface,
        "custompeer",
        allowed_ips_policy="custom",
        custom_allowed_ips="10.9.9.0/24",
    )
    assert peer["custom_allowed_ips"] == "10.9.9.0/24"
    updated = core.update_peer(
        wg0_interface, str(peer["id"]), allowed_ips_policy="vpn_only"
    )
    assert updated["allowed_ips_policy"] == "vpn_only"
    assert updated["custom_allowed_ips"] is None
