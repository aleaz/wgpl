import json
import sqlite3
import stat
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from wgpl import core, db
from wgpl.cli import _format_peer_id_display, _public_peer_rows, app


runner = CliRunner()


def test_public_peer_rows_redact_secrets() -> None:
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
    public = _public_peer_rows(cast(list[sqlite3.Row], rows), {"wg0": "1.1.1.1"})

    assert public == [
        {
            "id": "peer-id",
            "interface_id": "1",
            "name": "phone",
            "ip_address": "10.0.0.2",
            "public_key": "pub",
            "created_at": "2026-01-01T00:00:00+00:00",
            "dns": "1.1.1.1",
            "dns_override": "1.1.1.1",
            "status": "Active",
            "expires_at": None,
            "deleted_at": None,
        }
    ]
    assert "private_key" not in public[0]
    assert "preshared_key" not in public[0]


def test_peer_list_json_redacts_secrets(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "json_peer")

    result = runner.invoke(app, ["--json", "peer", "list"])

    assert result.exit_code == 0
    peers = json.loads(result.stdout)
    assert len(peers) == 1
    assert "private_key" not in peers[0]
    assert "preshared_key" not in peers[0]
    assert peers[0]["name"] == "json_peer"


def test_format_peer_id_full_when_single_peer() -> None:
    uid = "55c521ad-2d94-4689-8abc-123456789abc"
    assert _format_peer_id_display(uid, 1) == uid


def test_format_peer_id_short_when_multiple_peers() -> None:
    uid = "55c521ad-2d94-4689-8abc-123456789abc"
    assert _format_peer_id_display(uid, 3) == "55c521ad2d94"


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

    remove_result = runner.invoke(app, ["peer", "remove", wg0_interface, short_id])

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
    peers = json.loads(list_result.stdout)
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
    payload = json.loads(qr_result.stdout)
    assert payload == {
        "status": "success",
        "path": str(output_path),
        "peer_id": result["id"],
    }


def test_db_dump_cli_writes_hints_to_stderr(wg0_interface: str) -> None:
    result = runner.invoke(app, ["db", "dump"])

    assert result.exit_code == 0
    assert "chmod 600" in result.stderr
    assert "BEGIN TRANSACTION;" in result.stdout
    assert "Hint:" not in result.stdout


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
        ["--json", "peer", "add", "wg_dns", "Work", "--ip", "10.0.3.50", "--dns", "9.9.9.9"],
    )
    assert add_peer.exit_code == 0
    work_id = json.loads(add_peer.stdout)["id"]

    config = runner.invoke(app, ["peer", "config", work_id])
    assert config.exit_code == 0
    assert "DNS = 9.9.9.9" in config.stdout

    inherited = runner.invoke(app, ["--json", "peer", "add", "wg_dns", "Phone"])
    assert inherited.exit_code == 0
    phone_id = json.loads(inherited.stdout)["id"]
    inherited_config = runner.invoke(app, ["peer", "config", phone_id])
    assert "DNS = 1.1.1.1" in inherited_config.stdout


def test_cli_db_restore_json_stdin(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg0", "vpn.example.com", pubkey, "10.0.0.0/24", 51820)
    peer = core.add_peer("wg0", "phone", ip_address="10.0.0.3")
    peer_id = str(peer["id"])
    sql_script = "".join(core.dump_database_lines())

    result = runner.invoke(app, ["--json", "db", "restore", "-"], input=sql_script)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "success"
    assert payload["action"] == "restore"
    assert isinstance(payload["warnings"], list)
    restored = db.get_peer(peer_id)
    assert restored is not None
    assert restored["name"] == "phone"
