import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from typer.testing import CliRunner

from wgpl import core, wireguard
from wgpl.cli import app


runner = CliRunner()


@pytest.fixture
def iface_pubkey() -> str:
    return wireguard.generate_keypair().public_key


def _add_test_interface(name: str = "wg0", dns: str | None = None) -> str:
    pubkey = wireguard.generate_keypair().public_key
    args = [
        "--json",
        "interface",
        "add",
        name,
        "vpn.example.com",
        pubkey,
        "10.0.0.0/24",
    ]
    if dns is not None:
        args.extend(["--dns", dns])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    return pubkey


def test_json_interface_add_includes_dns(wgpl_db: str) -> None:
    result = runner.invoke(
        app,
        [
            "--json",
            "interface",
            "add",
            "wg0",
            "vpn.example.com",
            wireguard.generate_keypair().public_key,
            "10.0.0.0/24",
            "--dns",
            "1.1.1.1",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["dns"] == "1.1.1.1"
    assert payload["name"] == "wg0"


def test_json_interface_list(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["--json", "interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24", "--dns", "1.1.1.1"],
    )

    result = runner.invoke(app, ["--json", "interface", "list"])

    assert result.exit_code == 0
    interfaces = json.loads(result.stdout)
    assert len(interfaces) == 1
    assert interfaces[0]["dns"] == "1.1.1.1"


def test_json_interface_remove(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )

    result = runner.invoke(app, ["--json", "interface", "remove", "wg0"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"status": "success", "interface": "wg0", "force": False}


def test_json_interface_export(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )
    peer = json.loads(
        runner.invoke(app, ["--json", "peer", "add", "wg0", "phone"]).stdout
    )

    result = runner.invoke(app, ["--json", "interface", "export", "wg0"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "[Peer]" in payload["config"]
    assert peer["public_key"] in payload["config"]


def test_json_peer_add_effective_dns(wgpl_db: str) -> None:
    _add_test_interface("wg0", dns="1.1.1.1")

    result = runner.invoke(app, ["--json", "peer", "add", "wg0", "phone"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["dns"] == "1.1.1.1"
    assert len(payload["id"]) == 36


def test_json_peer_list_dns_fields(wgpl_db: str) -> None:
    _add_test_interface("wg0", dns="1.1.1.1")
    runner.invoke(app, ["--json", "peer", "add", "wg0", "inherited"])
    runner.invoke(app, ["--json", "peer", "add", "wg0", "override", "--dns", "9.9.9.9"])

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    peers = {p["name"]: p for p in json.loads(result.stdout)}
    assert peers["inherited"]["dns"] == "1.1.1.1"
    assert peers["inherited"]["dns_override"] is None
    assert peers["override"]["dns"] == "9.9.9.9"
    assert peers["override"]["dns_override"] == "9.9.9.9"
    assert "private_key" not in peers["inherited"]


def test_json_peer_list_dns_matches_peer_config(wgpl_db: str) -> None:
    _add_test_interface("wg0", dns="1.1.1.1")
    inherited = json.loads(
        runner.invoke(app, ["--json", "peer", "add", "wg0", "inherited"]).stdout
    )
    override = json.loads(
        runner.invoke(
            app, ["--json", "peer", "add", "wg0", "override", "--dns", "9.9.9.9"]
        ).stdout
    )

    list_result = runner.invoke(app, ["--json", "peer", "list"])
    assert list_result.exit_code == 0
    peers = {p["name"]: p for p in json.loads(list_result.stdout)}

    assert peers["inherited"]["status"] == "Active"
    assert peers["override"]["status"] == "Active"
    assert peers["inherited"]["dns"] == "1.1.1.1"
    assert peers["override"]["dns"] == "9.9.9.9"

    inherited_config = runner.invoke(app, ["peer", "config", inherited["id"]])
    override_config = runner.invoke(app, ["peer", "config", override["id"]])
    assert inherited_config.exit_code == 0
    assert override_config.exit_code == 0
    assert "DNS = 1.1.1.1" in inherited_config.stdout
    assert "DNS = 9.9.9.9" in override_config.stdout


def test_json_peer_remove_canonical_id(wgpl_db: str) -> None:
    _add_test_interface("wg0")
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "rm"]).stdout)
    short_id = peer["id"].replace("-", "")[:12]

    result = runner.invoke(app, ["--json", "peer", "remove", "wg0", short_id])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["id"] == peer["id"]
    assert payload["input"] == short_id
    assert payload["status"] == "success"


def test_json_peer_config_includes_private_key(wgpl_db: str) -> None:
    _add_test_interface("wg0")
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "cfg"]).stdout)

    result = runner.invoke(app, ["--json", "peer", "config", peer["id"]])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "PrivateKey" in payload["config"]


def test_json_peer_qr_ascii(wgpl_db: str) -> None:
    _add_test_interface("wg0")
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "qr"]).stdout)

    result = runner.invoke(app, ["--json", "peer", "qr", peer["id"]])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "qr" in payload
    assert payload["qr"]


def test_json_peer_qr_output_file(wgpl_db: str) -> None:
    _add_test_interface("wg0")
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "qrfile"]).stdout)
    output_path = Path(tempfile.mkdtemp()) / "peer.png"

    result = runner.invoke(
        app, ["--json", "peer", "qr", peer["id"], "-o", str(output_path)]
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "status": "success",
        "path": str(output_path),
        "peer_id": peer["id"],
    }


@patch.object(core, "sync_interface")
def test_json_apply(mock_sync: object, wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )

    result = runner.invoke(app, ["--json", "apply", "wg0"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {
        "status": "success",
        "action": "apply",
        "interface": "wg0",
    }


def test_json_flag_must_precede_subcommand(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )
    runner.invoke(app, ["peer", "add", "wg0", "phone"])

    result = runner.invoke(app, ["peer", "list", "--json"])

    # Global --json must precede the subcommand; trailing flag is not recognized.
    assert result.exit_code != 0 or not result.stdout.strip().startswith("[")


def test_json_interface_update(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )

    result = runner.invoke(
        app, ["--json", "interface", "update", "wg0", "--endpoint", "vpn2.example.com"]
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["endpoint"] == "vpn2.example.com"
    assert "re_export_clients" in payload["hints"]


def test_json_peer_update(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "phone"]).stdout)

    result = runner.invoke(
        app,
        ["--json", "peer", "update", "wg0", peer["id"], "--name", "Work"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["name"] == "Work"
    assert payload["id"] == peer["id"]


def test_json_validate(wgpl_db: str, iface_pubkey: str) -> None:
    runner.invoke(
        app,
        ["interface", "add", "wg0", "vpn.example.com", iface_pubkey, "10.0.0.0/24"],
    )
    runner.invoke(app, ["peer", "add", "wg0", "phone"])

    result = runner.invoke(app, ["--json", "validate", "wg0"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"status": "ok", "issues": []}
