"""Tests for routing topology validation (phase 3)."""

from __future__ import annotations

import datetime

from typer.testing import CliRunner

from wgpl import core, db, wireguard
from wgpl.cli import app
from wgpl.routing import AllowedIpsPolicy, PeerRole

runner = CliRunner()


def _add_iface() -> None:
    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")


def test_validate_overlapping_routed_networks_error(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
    )
    with db.transaction() as conn:
        keypair = wireguard.generate_keypair()
        db.add_peer(
            id="00000000-0000-4000-8000-000000000099",
            interface_id=1,
            name="site-b",
            ip_address="10.0.0.50",
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            role=PeerRole.SUBNET_ROUTER,
            routed_networks="192.168.10.0/25",
            conn=conn,
        )

    result = core.validate_state("wg0")
    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    codes = {issue["code"] for issue in issues}
    assert "overlapping_routed_networks" in codes


def test_validate_subnet_router_missing_keepalive_warning(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
    )

    result = core.validate_state("wg0")
    assert result["status"] == "warning"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(i["code"] == "subnet_router_missing_keepalive" for i in issues)


def test_validate_subnet_router_with_keepalive_ok(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        keepalive=25,
    )

    result = core.validate_state("wg0")
    assert result["status"] == "ok"


def test_validate_asymmetric_remote_access_warning(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )
    core.add_peer(
        "wg0",
        "site-b",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.20.0/24",
        allowed_ips_policy=AllowedIpsPolicy.VPN_ONLY,
        keepalive=25,
    )

    result = core.validate_state("wg0")
    assert result["status"] == "warning"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(i["code"] == "asymmetric_remote_access" for i in issues)


def test_validate_bidirectional_subnet_routers_ok(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )
    core.add_peer(
        "wg0",
        "site-b",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.20.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )

    result = core.validate_state("wg0")
    assert result["status"] == "ok"
    assert result["issues"] == []


def test_validate_expired_subnet_router_warning(wgpl_db: str) -> None:
    _add_iface()
    peer = core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        keepalive=25,
    )
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

    result = core.validate_state("wg0")
    assert result["status"] == "warning"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(i["code"] == "expired_subnet_router_routes_dropped" for i in issues)


def test_validate_subnet_router_missing_routed_networks(wgpl_db: str) -> None:
    _add_iface()
    peer = core.add_peer(
        "wg0",
        "bad-router",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        keepalive=25,
    )
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET routed_networks = NULL WHERE id = ?",
            (peer["id"],),
        )
        conn.commit()

    result = core.validate_state("wg0")
    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    assert any(i["code"] == "subnet_router_missing_routed_networks" for i in issues)


def test_assert_database_valid_allows_warnings(wgpl_db: str) -> None:
    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
    )
    core.assert_database_valid("wg0")


def test_cli_validate_warning_exits_zero(wgpl_db: str) -> None:
    import json

    _add_iface()
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
    )

    result = runner.invoke(app, ["--json", "validate", "wg0"], catch_exceptions=False)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "warning"
    assert any(
        i["code"] == "subnet_router_missing_keepalive" for i in payload["issues"]
    )
