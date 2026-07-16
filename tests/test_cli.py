import os
import sqlite3
import stat
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

import datetime
import uuid

from wgpl import core, db, wireguard
import wgpl.cli as cli_module
from wgpl.cli import _format_short_id, _public_peer_rows, app

from tests.json_helpers import json_status_payload, json_success_data


runner = CliRunner()


def _ensure_node(name: str) -> str:
    existing = db.get_node_by_name(name)
    if existing is not None:
        return str(existing["id"])
    node_id = str(uuid.uuid4())
    db.add_node(node_id, name, datetime.datetime.now(datetime.timezone.utc).isoformat())
    return node_id


def test_public_peer_rows_redact_secrets(wgpl_db: str) -> None:
    rows = [
        {
            "id": "peer-id",
            "interface_id": 1,
            "name": "phone",
            "ip_address": "10.0.0.2",
            "public_key": "pub",
            "private_key": "secret-private",
            "preshared_key": "secret-psk",
            "created_at": "2026-01-01T00:00:00+00:00",
            "dns": "1.1.1.1",
        }
    ]

    from typing import cast

    public = _public_peer_rows(cast(list[sqlite3.Row], rows), {1: "1.1.1.1"})

    assert public == [
        {
            "id": "peer-id",
            "interface_id": "1",
            "interface": None,
            "node_id": None,
            "name": "phone",
            "node": "phone",
            "ip_address": "10.0.0.2",
            "public_key": "pub",
            "created_at": "2026-01-01T00:00:00+00:00",
            "dns": "1.1.1.1",
            "dns_override": "1.1.1.1",
            "desc": None,
            "mtu": None,
            "mtu_override": None,
            "keepalive": None,
            "keepalive_override": None,
            "status": "Active",
            "expires_at": None,
            "deleted_at": None,
            "role": "endpoint",
            "routed_networks": None,
            "allowed_ips_policy": "vpn_only",
            "custom_allowed_ips": None,
            "hub_allowed_ips": [],
            "client_allowed_ips": [],
        }
    ]
    assert "private_key" not in public[0]
    assert "preshared_key" not in public[0]


def test_peer_list_json_redacts_secrets(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "json_peer")

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    peers = json_success_data(result)
    assert len(peers) == 1
    assert "private_key" not in peers[0]
    assert "preshared_key" not in peers[0]
    assert peers[0]["name"] == "json_peer"
    assert peers[0]["interface"] == "wg0"
    assert peers[0]["interface_id"]


def test_peer_show_json_includes_interface_name(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "show_iface")
    peer_id = str(peer["id"])

    result = runner.invoke(app, ["--json", "peer", "show", peer_id])

    assert result.exit_code == 0
    payload = json_success_data(result)
    assert payload["interface"] == "wg0"
    assert payload["interface_id"]


def test_peer_list_json_dual_interface_names(wgpl_db: str) -> None:
    pk0 = wireguard.generate_keypair().public_key
    pk1 = wireguard.generate_keypair().public_key
    runner.invoke(
        app, ["interface", "add", "wg0", "vpn0.example.com", pk0, "10.0.0.0/24"]
    )
    runner.invoke(
        app,
        [
            "interface",
            "add",
            "wg1",
            "vpn1.example.com",
            pk1,
            "10.0.1.0/24",
            "--port",
            "51821",
        ],
    )
    core.add_peer("wg0", "on_wg0")
    core.add_peer("wg1", "on_wg1")

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    by_name = {p["name"]: p["interface"] for p in json_success_data(result)}
    assert by_name == {"on_wg0": "wg0", "on_wg1": "wg1"}


def test_cli_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("wgpl ")
    assert "1." in result.stdout or "0.0.0+unknown" in result.stdout

    result_v = runner.invoke(app, ["-V"])
    assert result_v.exit_code == 0
    assert result_v.stdout.strip().startswith("wgpl ")


def test_peer_show_json_redacts_private_key(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "show_peer")
    peer_id = str(peer["id"])

    result = runner.invoke(app, ["--json", "peer", "show", peer_id])

    assert result.exit_code == 0
    payload = json_success_data(result)
    assert "private_key" not in payload
    assert "preshared_key" not in payload
    assert payload["name"] == "show_peer"


def test_peer_show_human_hides_psk_by_default(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "psk_peer")
    peer_id = str(peer["id"])
    full = db.get_peer(peer_id)
    assert full is not None
    assert full["preshared_key"]

    result = runner.invoke(app, ["peer", "show", peer_id])

    assert result.exit_code == 0
    assert full["preshared_key"] not in result.stdout


def test_peer_show_show_secrets_reveals_psk(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "psk_peer2")
    peer_id = str(peer["id"])
    full = db.get_peer(peer_id)
    assert full is not None
    assert full["preshared_key"]

    result = runner.invoke(app, ["peer", "show", peer_id, "--show-secrets"])

    assert result.exit_code == 0
    assert full["preshared_key"] in result.stdout


def test_peer_list_json_includes_desc_mtu_keepalive(wg0_interface: str) -> None:
    core.update_interface(wg0_interface, mtu=1420, keepalive=25)
    core.add_peer(
        wg0_interface,
        "json_fields",
        desc="laptop",
        mtu=1280,
        keepalive=15,
    )

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    peer = json_success_data(result)[0]
    assert peer["desc"] == "laptop"
    assert peer["mtu"] == 1280
    assert peer["mtu_override"] == 1280
    assert peer["keepalive"] == 15
    assert peer["keepalive_override"] == 15


def test_peer_list_json_inherits_iface_mtu_keepalive(wg0_interface: str) -> None:
    core.update_interface(wg0_interface, mtu=1420, keepalive=25)
    core.add_peer(wg0_interface, "inherit_fields")

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    peer = json_success_data(result)[0]
    assert peer["desc"] is None
    assert peer["mtu"] == 1420
    assert peer["mtu_override"] is None
    assert peer["keepalive"] == 25
    assert peer["keepalive_override"] is None


def test_peer_row_to_public_dict_matches_list_json(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "match_peer")
    peer_id = str(peer["id"])

    list_result = runner.invoke(app, ["--json", "peer", "list"])
    show_result = runner.invoke(app, ["--json", "peer", "show", peer_id])

    assert list_result.exit_code == 0
    assert show_result.exit_code == 0
    list_payload = json_success_data(list_result)[0]
    show_payload = json_success_data(show_result)
    assert show_payload == list_payload


def test_format_short_id_strips_dashes_and_truncates() -> None:
    uid = "55c521ad-2d94-4689-8abc-123456789abc"
    assert _format_short_id(uid) == "55c521ad2d94"


def test_peer_list_human_shows_short_id_even_when_alone(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "alone_peer")
    peer_id = result["id"]
    assert peer_id is not None
    short_id = peer_id.replace("-", "")[:12]

    list_result = runner.invoke(app, ["peer", "list"])

    assert list_result.exit_code == 0
    assert short_id in list_result.stdout
    assert peer_id not in list_result.stdout


def test_peer_show_human_shows_full_uuid(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "show_uuid")
    peer_id = result["id"]
    assert peer_id is not None

    show_result = runner.invoke(app, ["peer", "show", peer_id])

    assert show_result.exit_code == 0
    assert peer_id in show_result.stdout


def test_peer_config_accepts_short_prefix(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "prefix_peer")
    peer_id = result["id"]
    assert peer_id is not None
    short_id = peer_id.replace("-", "")[:12]

    config_result = runner.invoke(app, ["peer", "config", short_id])

    assert config_result.exit_code == 0
    assert "PrivateKey" in config_result.stdout


def test_peer_remove_accepts_short_prefix(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "remove_me")
    peer_id = result["id"]
    assert peer_id is not None
    short_id = peer_id.replace("-", "")[:12]

    remove_result = runner.invoke(app, ["peer", "remove", short_id, "-i", wg0_interface])

    assert remove_result.exit_code == 0
    peer = db.get_peer(peer_id)
    assert peer is not None
    assert peer["deleted_at"] is not None


def test_peer_list_json_returns_full_uuid(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "uuid_peer")
    peer_id = result["id"]
    assert peer_id is not None

    list_result = runner.invoke(app, ["--json", "peer", "list"])

    assert list_result.exit_code == 0
    peers = json_success_data(list_result)
    assert peers[0]["id"] == peer_id
    assert len(peers[0]["id"]) == 36


def test_peer_qr_ascii_default(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "ascii_qr")

    assert result["id"] is not None
    qr_result = runner.invoke(app, ["peer", "qr", result["id"]])

    assert qr_result.exit_code == 0
    assert "█" in qr_result.stdout or "▀" in qr_result.stdout


def test_peer_qr_output_png(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "png_qr")
    output_path = Path(tempfile.mkdtemp()) / "peer.png"

    assert result["id"] is not None
    qr_result = runner.invoke(app, ["peer", "qr", result["id"], "-o", str(output_path)])

    assert qr_result.exit_code == 0
    assert qr_result.stdout == ""
    assert output_path.exists()
    assert output_path.read_bytes().startswith(b"\x89PNG")
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600


def test_peer_qr_output_json(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "json_qr")
    output_path = Path(tempfile.mkdtemp()) / "peer.png"

    assert result["id"] is not None
    qr_result = runner.invoke(
        app, ["--json", "peer", "qr", result["id"], "-o", str(output_path)]
    )

    assert qr_result.exit_code == 0
    payload = json_status_payload(qr_result)
    assert payload == {
        "status": "success",
        "path": str(output_path),
        "peer_id": result["id"],
    }


def test_db_dump_cli_writes_hints_to_stderr(wg0_interface: str) -> None:
    result = runner.invoke(app, ["db", "dump"])

    assert result.exit_code == 0
    assert "Warning: Output is a binary SQLite database file." not in result.stderr
    assert b"SQLite format 3" in result.stdout_bytes


def test_peer_add_with_ip_and_dns_cli(wgpl_db: str) -> None:
    from wgpl import wireguard

    public_key = wireguard.generate_keypair().public_key
    add_iface = runner.invoke(
        app,
        [
            "interface",
            "add",
            "wg_dns",
            "vpn.example.com",
            public_key,
            "10.0.3.0/24",
            "--dns",
            "1.1.1.1",
        ],
    )
    assert add_iface.exit_code == 0

    add_peer = runner.invoke(
        app,
        [
            "--json",
            "peer",
            "add",
            "Work",
            "-i",
            "wg_dns",
            "--ip",
            "10.0.3.50",
            "--dns",
            "9.9.9.9",
        ],
    )
    assert add_peer.exit_code == 0
    work_id = json_success_data(add_peer)["id"]

    config = runner.invoke(app, ["peer", "config", work_id])
    assert config.exit_code == 0
    assert "DNS = 9.9.9.9" in config.stdout

    inherited = runner.invoke(app, ["--json", "peer", "add", "Phone", "-i", "wg_dns"])
    assert inherited.exit_code == 0
    phone_id = json_success_data(inherited)["id"]
    inherited_config = runner.invoke(app, ["peer", "config", phone_id])
    assert "DNS = 1.1.1.1" in inherited_config.stdout


def test_cli_db_restore_json_stdin(wgpl_db: str) -> None:
    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24", 51820)
    peer = core.add_peer("wg0", "phone", ip_address="10.0.0.3")
    peer_id = str(peer["id"])

    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.unlink(path)
    core.dump_database(path)
    with open(path, "rb") as f:
        binary_db = f.read()
    os.remove(path)

    result = runner.invoke(
        app, ["--json", "db", "restore", "--yes", "-"], input=binary_db
    )

    assert result.exit_code == 0
    payload = json_status_payload(result)
    assert payload["status"] == "success"
    assert payload["action"] == "restore"
    assert isinstance(payload["warnings"], list)
    restored = db.get_peer(peer_id)
    assert restored is not None
    assert restored["name"] == "phone"


def test_cli_db_restore_requires_yes(wgpl_db: str) -> None:
    result = runner.invoke(app, ["--json", "db", "restore", "/nonexistent.db"])

    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert "--yes" in payload["message"]


def test_peer_history_limit_capped(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    result = runner.invoke(
        app, ["peer", "history", str(peer["id"]), "-i", wg0_interface, "--limit", "1001"]
    )

    assert result.exit_code == 1
    assert "limit must be <=" in result.stderr


def test_db_restore_stdin_size_limit(
    wgpl_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_module, "_MAX_RESTORE_STDIN_BYTES", 16)
    binary_db = b"x" * 17
    result = runner.invoke(
        app, ["--json", "db", "restore", "--yes", "-"], input=binary_db
    )

    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert "exceeds" in payload["message"]


def test_cli_peer_config_interface_disambiguates(wgpl_db: str) -> None:
    from wgpl import wireguard

    pk1 = wireguard.generate_keypair().public_key
    pk2 = wireguard.generate_keypair().public_key
    iface_a = db.add_interface("wg0", "vpn1.example.com", pk1, "10.0.0.0/24", 51820)
    iface_b = db.add_interface("wg1", "vpn2.example.com", pk2, "10.0.1.0/24", 51821)
    keypair = wireguard.generate_keypair()
    db.add_peer(
        id="55c521ad-2d94-4689-8abc-111111111111",
        interface_id=iface_a,
        node_id=_ensure_node("phone"),
        ip_address="10.0.0.2",
        public_key=keypair.public_key,
        private_key=keypair.private_key,
        created_at="2026-01-01T00:00:00+00:00",
    )
    keypair_b = wireguard.generate_keypair()
    db.add_peer(
        id="55c521ad-ff94-4689-8abc-222222222222",
        interface_id=iface_b,
        node_id=_ensure_node("laptop"),
        ip_address="10.0.1.2",
        public_key=keypair_b.public_key,
        private_key=keypair_b.private_key,
        created_at="2026-01-01T00:00:00+00:00",
    )

    ambiguous = runner.invoke(app, ["peer", "config", "55c521ad"])
    assert ambiguous.exit_code == 1

    result = runner.invoke(app, ["peer", "config", "55c521ad", "--interface", "wg0"])
    assert result.exit_code == 0
    assert "vpn1.example.com:51820" in result.stdout
    assert "vpn2.example.com" not in result.stdout

def test_peer_list_nonexistent_db(tmp_path) -> None:
    """Ensure read-only commands do not create the database if it doesn't exist."""
    db_path = tmp_path / "missing.db"
    os.environ["WGPL_DB_PATH"] = str(db_path)
    
    result = runner.invoke(app, ["peer", "list"])
    
    assert result.exit_code == 1
    assert not db_path.exists()
    assert "Database does not exist" in result.stdout or "Database does not exist" in result.stderr
