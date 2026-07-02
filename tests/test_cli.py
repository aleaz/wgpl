import json

from typer.testing import CliRunner

from wgpl import core, db
from wgpl.cli import _format_peer_id_display, _public_peer_rows, app


runner = CliRunner()


def test_public_peer_rows_redact_secrets() -> None:
    rows = [
        {
            "id": "peer-id",
            "interface": "wg0",
            "name": "phone",
            "ip_address": "10.0.0.2",
            "public_key": "pub",
            "private_key": "secret-private",
            "preshared_key": "secret-psk",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
    ]

    public = _public_peer_rows(rows)

    assert public == [
        {
            "id": "peer-id",
            "interface": "wg0",
            "name": "phone",
            "ip_address": "10.0.0.2",
            "public_key": "pub",
            "created_at": "2026-01-01T00:00:00+00:00",
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
    short_id = peer_id.replace("-", "")[:12]

    config_result = runner.invoke(app, ["peer", "config", short_id])

    assert config_result.exit_code == 0
    assert "PrivateKey" in config_result.stdout


def test_peer_remove_accepts_short_prefix(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "remove_me")
    peer_id = result["id"]
    short_id = peer_id.replace("-", "")[:12]

    remove_result = runner.invoke(app, ["peer", "remove", wg0_interface, short_id])

    assert remove_result.exit_code == 0
    assert db.get_peer(peer_id) is None


def test_peer_list_json_returns_full_uuid(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "uuid_peer")
    peer_id = result["id"]

    list_result = runner.invoke(app, ["--json", "peer", "list"])

    assert list_result.exit_code == 0
    peers = json.loads(list_result.stdout)
    assert peers[0]["id"] == peer_id
    assert len(peers[0]["id"]) == 36
