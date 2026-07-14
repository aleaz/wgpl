"""CLI tests for routing flags."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from wgpl.cli import app
from wgpl import core, db
from wgpl.routing import AllowedIpsPolicy, PeerRole


runner = CliRunner()


def _invoke(args: list[str]):
    return runner.invoke(app, args, catch_exceptions=False)


@pytest.fixture
def seeded(wgpl_db: str) -> dict:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface(
        "wg0",
        "vpn.example.com",
        pubkey,
        "10.0.0.0/24",
        routed_networks="10.50.0.0/16",
    )
    peer = core.add_peer("wg0", "laptop")
    return {"peer": peer}


def test_cli_peer_add_subnet_router(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")

    result = _invoke(
        [
            "peer",
            "add",
            "-i", "wg0",
            "site-a-gw",
            "--role",
            "subnet_router",
            "--routed-networks",
            "192.168.10.0/24",
            "--allowed-ips-policy",
            "all_remote_networks",
            "--keepalive",
            "25",
        ]
    )
    assert result.exit_code == 0

    peers = db.list_peers(1)
    site = next(p for p in peers if p["name"] == "site-a-gw")
    assert site["role"] == PeerRole.SUBNET_ROUTER
    assert site["routed_networks"] == "192.168.10.0/24"
    assert site["allowed_ips_policy"] == AllowedIpsPolicy.ALL_REMOTE_NETWORKS

    config = core.get_interface_config("wg0")
    assert "192.168.10.0/24" in config


def test_cli_peer_config_derived_by_default(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(["peer", "config", peer_id])
    assert result.exit_code == 0
    assert "AllowedIPs = 10.0.0.0/24" in result.stdout


def test_cli_peer_config_json_derived(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(["--json", "peer", "config", peer_id])
    assert result.exit_code == 0
    payload = json.loads(result.stdout).get("data", json.loads(result.stdout))
    assert "AllowedIPs = 10.0.0.0/24" in payload["config"]
    assert payload["allowed_ips_source"] == "derived"
    assert payload["client_allowed_ips"] == ["10.0.0.0/24"]


def test_cli_peer_config_json_override(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(
        ["--json", "peer", "config", peer_id, "--allowed-ips", "0.0.0.0/0"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout).get("data", json.loads(result.stdout))
    assert payload["allowed_ips_source"] == "override"
    assert payload["client_allowed_ips"] == ["0.0.0.0/0"]
    assert "AllowedIPs = 0.0.0.0/0" in payload["config"]


def test_cli_peer_list_json_includes_hub_allowed_ips(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")
    core.add_peer(
        "wg0",
        "site-a-gw",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )

    result = _invoke(["--json", "peer", "list"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout).get("data", json.loads(result.stdout))
    site = next(p for p in payload if p["name"] == "site-a-gw")
    assert site["hub_allowed_ips"] == [
        f"{site['ip_address']}/32",
        "192.168.10.0/24",
    ]


def test_cli_peer_explain_lan_to_lan(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")
    core.add_peer(
        "wg0",
        "site-a",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.10.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )
    site_b = core.add_peer(
        "wg0",
        "site-b",
        role=PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.20.0/24",
        allowed_ips_policy=AllowedIpsPolicy.ALL_REMOTE_NETWORKS,
        keepalive=25,
    )

    result = _invoke(["--json", "peer", "explain", site_b["id"]])
    assert result.exit_code == 0
    payload = json.loads(result.stdout).get("data", json.loads(result.stdout))
    assert payload["hub_allowed_ips"] == [
        f"{site_b['ip_address']}/32",
        "192.168.20.0/24",
    ]
    assert "192.168.10.0/24" in payload["client_allowed_ips"]
    assert len(payload["lan_to_lan_checklist"]) == 1
    assert payload["lan_to_lan_checklist"][0]["remote_peer"] == "site-a"
    assert payload["lan_to_lan_checklist"][0]["complete"] is True


def test_cli_peer_update_routing_audit(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")
    peer = core.add_peer("wg0", "site-a")

    result = _invoke(
        [
            "--json",
            "peer",
            "update",
            "-i", "wg0",
            peer["id"],
            "--role",
            "subnet_router",
            "--routed-networks",
            "192.168.10.0/24",
            "--allowed-ips-policy",
            "all_remote_networks",
        ]
    )
    assert result.exit_code == 0

    events = core.list_peer_audit_history(peer["id"], "wg0")
    updated = next(e for e in events if e["event_type"] == "updated")
    fields = updated["metadata"]["fields"]
    assert "role" in fields
    assert "routed_networks" in fields
    assert "allowed_ips_policy" in fields


def test_cli_interface_update_routed_networks(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")

    result = _invoke(
        [
            "--json",
            "interface",
            "update",
            "wg0",
            "--routed-networks",
            "10.50.0.0/16,192.168.1.0/24",
        ]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout).get("data", json.loads(result.stdout))
    assert payload["routed_networks"] == "10.50.0.0/16,192.168.1.0/24"


def test_cli_peer_add_rejects_endpoint_with_routed_networks(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24")

    result = _invoke(
        [
            "peer",
            "add",
            "-i", "wg0",
            "bad",
            "--routed-networks",
            "192.168.10.0/24",
        ]
    )
    assert result.exit_code == 1
    assert "endpoint peers must not have routed_networks" in result.stderr
