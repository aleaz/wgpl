"""Unit and integration tests for routing.py and derived AllowedIPs export."""

from __future__ import annotations

import datetime
import uuid

import pytest

from wgpl import core, db, routing, wireguard
from wgpl.exceptions import PeerAlreadyExistsError, WgplException
from wgpl.routing import AllowedIpsPolicy, PeerRole


def _set_peer_routing(
    peer_id: str,
    *,
    role: str = PeerRole.SUBNET_ROUTER,
    routed_networks: str | None = None,
    allowed_ips_policy: str = AllowedIpsPolicy.VPN_ONLY,
    custom_allowed_ips: str | None = None,
) -> None:
    with db.get_db() as conn:
        conn.execute(
            """
            UPDATE peers
            SET role = ?, routed_networks = ?, allowed_ips_policy = ?,
                custom_allowed_ips = ?
            WHERE id = ?
            """,
            (role, routed_networks, allowed_ips_policy, custom_allowed_ips, peer_id),
        )
        conn.commit()


def _set_interface_routed_networks(interface_id: int, routed_networks: str) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE interfaces SET routed_networks = ? WHERE id = ?",
            (routed_networks, interface_id),
        )
        conn.commit()


def test_normalize_cidr_list_deduplicates_and_sorts() -> None:
    assert routing.normalize_cidr_list("192.168.1.0/24,10.0.0.0/8,192.168.1.0/24") == (
        "10.0.0.0/8,192.168.1.0/24"
    )


def test_parse_cidr_list_rejects_empty_entry() -> None:
    with pytest.raises(WgplException, match="cannot be empty"):
        routing.parse_cidr_list("10.0.0.0/8,,192.168.0.0/16")


def test_resolve_hub_allowed_ips_endpoint_is_tunnel_only(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    assert routing.resolve_hub_allowed_ips(peer) == [f"{peer['ip_address']}/32"]


def test_resolve_hub_allowed_ips_subnet_router_includes_lan(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "site-a")
    _set_peer_routing(
        peer["id"],
        routed_networks="192.168.10.0/24",
    )
    row = db.get_peer(peer["id"])
    assert row is not None
    assert routing.resolve_hub_allowed_ips(row) == [
        f"{row['ip_address']}/32",
        "192.168.10.0/24",
    ]


def test_resolve_client_vpn_only(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    assert routing.resolve_client_allowed_ips(peer, iface, [peer]) == ["10.0.0.0/24"]


def test_resolve_client_full_tunnel(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    _set_peer_routing(
        peer["id"],
        role=PeerRole.ENDPOINT,
        allowed_ips_policy=AllowedIpsPolicy.FULL_TUNNEL,
    )
    row = db.get_peer(peer["id"])
    assert row is not None
    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    assert routing.resolve_client_allowed_ips(row, iface, [row]) == ["0.0.0.0/0"]


def test_resolve_client_split_tunnel(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    _set_peer_routing(
        peer["id"],
        role=PeerRole.ENDPOINT,
        allowed_ips_policy=AllowedIpsPolicy.SPLIT_TUNNEL,
    )
    _set_interface_routed_networks(int(wg0_interface), "10.50.0.0/16")
    row = db.get_peer(peer["id"])
    assert row is not None
    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    result = routing.resolve_client_allowed_ips(row, iface, [row])
    assert result == ["10.0.0.0/24", "10.50.0.0/16"]


def test_resolve_client_all_remote_excludes_own_lan(wg0_interface: str) -> None:
    site_a = core.add_peer(wg0_interface, "site-a")
    site_b = core.add_peer(wg0_interface, "site-b")
    _set_peer_routing(
        site_a["id"],
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
    )
    _set_peer_routing(
        site_b["id"],
        routed_networks="192.168.20.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
    )
    row_a = db.get_peer(site_a["id"])
    row_b = db.get_peer(site_b["id"])
    assert row_a is not None and row_b is not None
    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    active = [row_a, row_b]

    a_result = routing.resolve_client_allowed_ips(row_a, iface, active)
    assert "192.168.20.0/24" in a_result
    assert "192.168.10.0/24" not in a_result

    b_result = routing.resolve_client_allowed_ips(row_b, iface, active)
    assert "192.168.10.0/24" in b_result
    assert "192.168.20.0/24" not in b_result


def test_resolve_hub_allowed_ips_subnet_router_multiple_lans(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "site-multi")
    multi_lans = "192.168.10.0/24,172.16.20.0/24,10.50.0.0/16"
    _set_peer_routing(peer["id"], routed_networks=multi_lans)
    row = db.get_peer(peer["id"])
    assert row is not None

    hub_ips = routing.resolve_hub_allowed_ips(row)
    assert hub_ips[0] == f"{row['ip_address']}/32"
    assert set(hub_ips[1:]) == {
        "192.168.10.0/24",
        "172.16.20.0/24",
        "10.50.0.0/16",
    }


def test_resolve_client_all_remote_includes_multi_lan_from_other_router(
    wg0_interface: str,
) -> None:
    site_multi = core.add_peer(wg0_interface, "site-multi")
    site_b = core.add_peer(wg0_interface, "site-b")
    multi_lans = "192.168.10.0/24,172.16.20.0/24,10.50.0.0/16"
    _set_peer_routing(site_multi["id"], routed_networks=multi_lans)
    _set_peer_routing(
        site_b["id"],
        routed_networks="192.168.30.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
    )
    row_multi = db.get_peer(site_multi["id"])
    row_b = db.get_peer(site_b["id"])
    assert row_multi is not None and row_b is not None
    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    active = [row_multi, row_b]

    b_result = routing.resolve_client_allowed_ips(row_b, iface, active)
    for cidr in ("192.168.10.0/24", "172.16.20.0/24", "10.50.0.0/16"):
        assert cidr in b_result
    assert "192.168.30.0/24" not in b_result


def test_mixed_topology_endpoints_and_three_subnet_routers(
    wg0_interface: str,
) -> None:
    """20-notebook + 5-router style mix: endpoints stay minimal; routers see remote LANs."""
    laptop_a = core.add_peer(wg0_interface, "laptop-a")
    laptop_b = core.add_peer(wg0_interface, "laptop-b")
    road_warrior = core.add_peer(wg0_interface, "road-warrior")
    site_a = core.add_peer(wg0_interface, "site-a")
    site_b = core.add_peer(wg0_interface, "site-b")
    site_c = core.add_peer(wg0_interface, "site-c")

    _set_peer_routing(
        road_warrior["id"],
        role=PeerRole.ENDPOINT,
        allowed_ips_policy=AllowedIpsPolicy.FULL_TUNNEL,
    )
    for site, lan in (
        (site_a, "192.168.10.0/24"),
        (site_b, "192.168.20.0/24"),
        (site_c, "192.168.30.0/24"),
    ):
        _set_peer_routing(
            site["id"],
            routed_networks=lan,
            allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        )

    iface = db.get_interface(int(wg0_interface))
    assert iface is not None
    active_rows = [
        row
        for pid in (
            laptop_a["id"],
            laptop_b["id"],
            road_warrior["id"],
            site_a["id"],
            site_b["id"],
            site_c["id"],
        )
        if (row := db.get_peer(pid)) is not None
    ]
    assert len(active_rows) == 6

    for endpoint_id in (laptop_a["id"], laptop_b["id"]):
        row = db.get_peer(endpoint_id)
        assert row is not None
        client_ips = routing.resolve_client_allowed_ips(row, iface, active_rows)
        assert client_ips == ["10.0.0.0/24"]
        for lan in ("192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"):
            assert lan not in client_ips

    road_row = db.get_peer(road_warrior["id"])
    assert road_row is not None
    assert routing.resolve_client_allowed_ips(road_row, iface, active_rows) == [
        "0.0.0.0/0"
    ]

    remote_lans = {"192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"}
    for site_id, own_lan in (
        (site_a["id"], "192.168.10.0/24"),
        (site_b["id"], "192.168.20.0/24"),
        (site_c["id"], "192.168.30.0/24"),
    ):
        row = db.get_peer(site_id)
        assert row is not None
        client_ip_set = set(routing.resolve_client_allowed_ips(row, iface, active_rows))
        assert own_lan not in client_ip_set
        assert remote_lans - {own_lan} <= client_ip_set

    config = core.get_interface_config(wg0_interface)
    for site_id, lan in (
        (site_a["id"], "192.168.10.0/24"),
        (site_b["id"], "192.168.20.0/24"),
        (site_c["id"], "192.168.30.0/24"),
    ):
        row = db.get_peer(site_id)
        assert row is not None
        assert lan in config
        assert f"{row['ip_address']}/32" in config


def test_get_interface_config_subnet_router_allowed_ips(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "site-a")
    _set_peer_routing(peer["id"], routed_networks="192.168.10.0/24")
    row = db.get_peer(peer["id"])
    assert row is not None

    config = core.get_interface_config(wg0_interface)
    assert (
        f"AllowedIPs = {row['ip_address']}/32,192.168.10.0/24" in config
        or f"AllowedIPs = 192.168.10.0/24,{row['ip_address']}/32" in config
    )


def test_get_peer_config_derived_vpn_only_by_default(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    config = core.get_peer_config(peer["id"])
    assert "AllowedIPs = 10.0.0.0/24" in config


def test_get_peer_config_override_still_works(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "laptop")
    config = core.get_peer_config(peer["id"], allowed_ips="0.0.0.0/0")
    assert "AllowedIPs = 0.0.0.0/0" in config


def test_assert_peer_activation_rejects_overlapping_routed_networks(
    wg0_interface: str,
) -> None:
    site_a = core.add_peer(wg0_interface, "site-a")
    _set_peer_routing(site_a["id"], routed_networks="192.168.10.0/24")

    keypair = wireguard.generate_keypair()
    with db.transaction() as conn:
        iface_id = int(wg0_interface)
        iface = db.get_interface(iface_id, conn=conn)
        assert iface is not None
        node_b_id = str(uuid.uuid4())
        db.add_node(
            node_b_id,
            "site-b",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
            conn=conn,
        )
        db.add_peer(
            id="00000000-0000-4000-8000-000000000099",
            interface_id=iface_id,
            node_id=node_b_id,
            ip_address="10.0.0.50",
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            conn=conn,
        )
        conn.execute(
            """
            UPDATE peers
            SET role = 'subnet_router', routed_networks = '192.168.10.0/25'
            WHERE id = '00000000-0000-4000-8000-000000000099'
            """
        )
        peer_b = db.get_peer("00000000-0000-4000-8000-000000000099", conn=conn)
        assert peer_b is not None
        from wgpl import integrity

        with pytest.raises(PeerAlreadyExistsError, match="overlaps"):
            integrity.assert_peer_activation(peer_b, iface, conn=conn)


def test_validate_database_rejects_malicious_routed_networks(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "site-a")
    with db.get_db() as conn:
        conn.execute(
            """
            UPDATE peers
            SET role = 'subnet_router', routed_networks = ?
            WHERE id = ?
            """,
            ("192.168.0.0/16\n[Peer]", peer["id"]),
        )
        conn.commit()

    from wgpl import integrity

    result = integrity.validate_database(full=True)
    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(
        "unsafe control characters" in str(issue.get("detail", ""))
        for issue in issues
        if isinstance(issue, dict)
    )


def test_expired_subnet_router_drops_from_hub_config(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "site-a")
    _set_peer_routing(peer["id"], routed_networks="192.168.10.0/24")

    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?",
            (
                (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(hours=1)
                ).isoformat(),
                peer["id"],
            ),
        )
        conn.commit()

    config = core.get_interface_config(wg0_interface)
    assert "192.168.10.0/24" not in config
