import json

import pytest
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


def test_cli_peer_remove_already_deleted_raises_not_found(wgpl_db: str) -> None:
    _setup_interface()
    peer = core.add_peer("wg0", "phone")
    assert peer["id"] is not None

    first = runner.invoke(app, ["peer", "remove", "wg0", peer["id"]])
    assert first.exit_code == 0

    second = runner.invoke(app, ["peer", "remove", "wg0", peer["id"]])
    assert second.exit_code == 1
    assert "WGPL Error" in second.stderr


def test_cli_interface_remove_not_found(wgpl_db: str) -> None:
    result = runner.invoke(app, ["interface", "remove", "missing"])

    assert result.exit_code == 1


def test_cli_peer_remove_interface_mismatch_reports_wgpl_error(
    wgpl_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")
    pubkey = wireguard.generate_keypair().public_key
    runner.invoke(
        app,
        ["interface", "add", "wg1", "vpn2.example.com", pubkey, "10.0.1.0/24"],
    )
    monkeypatch.setattr(
        core,
        "resolve_peer_ref",
        lambda ref, iface=None, active_only=True: peer["id"],
    )

    assert peer["id"] is not None
    result = runner.invoke(app, ["peer", "remove", "wg1", peer["id"]])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "does not belong" in result.stderr
    assert "Unexpected Error" not in result.stderr


def test_cli_interface_port_conflict(wgpl_db: str) -> None:
    _setup_interface("wg0")
    pubkey = wireguard.generate_keypair().public_key
    
    result = runner.invoke(app, [
        "interface", "add", "wg1", "vpn.example.com", pubkey, "10.0.1.0/24", "--port", "51820"
    ])
    
    assert result.exit_code == 1
    assert "Port 51820 is already used" in result.output


def test_cli_interface_pool_conflict(wgpl_db: str) -> None:
    _setup_interface("wg0")
    pubkey = wireguard.generate_keypair().public_key
    
    result = runner.invoke(app, [
        "interface", "add", "wg1", "vpn.example.com", pubkey, "10.0.0.0/24", "--port", "51821"
    ])
    
    assert result.exit_code == 1
    assert "Address pool 10.0.0.0/24 is already used" in result.output
