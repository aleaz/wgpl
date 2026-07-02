import json

from typer.testing import CliRunner

from wgpl import core
from wgpl.cli import _public_peer_rows, app


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
