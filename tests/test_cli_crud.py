import json

from typer.testing import CliRunner

from wgpl import core, db, wireguard
from wgpl.cli import app


runner = CliRunner()


def _setup_interface(name: str = "wg0", dns: str | None = None) -> str:
    pubkey = wireguard.generate_keypair().public_key
    args = [
        "interface",
        "add",
        name,
        "vpn.example.com",
        pubkey,
        "10.0.0.0/24",
    ]
    if dns:
        args.extend(["--dns", dns])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.stdout
    return pubkey


def test_cli_validate_error_exit_code(wgpl_db: str) -> None:
    _setup_interface()
    peer = core.add_peer("wg0", "bad")
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET ip_address = ? WHERE id = ?",
            ("10.0.1.50", peer["id"]),
        )
        conn.commit()

    result = runner.invoke(app, ["validate", "wg0"])

    assert result.exit_code == 1


def test_cli_interface_update_no_fields(wgpl_db: str) -> None:
    _setup_interface()

    result = runner.invoke(app, ["interface", "update", "wg0"])

    assert result.exit_code == 1


def test_cli_peer_update_ip_hints_on_stderr(wgpl_db: str) -> None:
    _setup_interface()
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "wg0", "p"]).stdout)

    result = runner.invoke(
        app, ["peer", "update", "wg0", peer["id"], "--ip", "10.0.0.50"]
    )

    assert result.exit_code == 0
    assert "apply" in result.stderr.lower() or "sync" in result.stderr.lower()


def test_cli_interface_remove_not_found(wgpl_db: str) -> None:
    result = runner.invoke(app, ["interface", "remove", "missing"])

    assert result.exit_code == 1
