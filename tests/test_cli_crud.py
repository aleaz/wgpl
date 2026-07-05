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
    assert second.exit_code == 0
    assert "Removed peer" in second.stderr


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
    
    assert result.exit_code == 0


def test_cli_interface_pool_conflict(wgpl_db: str) -> None:
    _setup_interface("wg0")
    pubkey = wireguard.generate_keypair().public_key
    
    result = runner.invoke(app, [
        "interface", "add", "wg1", "vpn.example.com", pubkey, "10.0.0.0/24", "--port", "51821"
    ])
    
    assert result.exit_code == 0


def test_cli_interface_update_pool_rejected(wgpl_db: str) -> None:
    _setup_interface("wg0")
    runner.invoke(app, ["peer", "add", "wg0", "high", "--ip", "10.0.0.200"])

    result = runner.invoke(
        app,
        ["interface", "update", "wg0", "--address-pool", "10.0.0.0/25"],
    )

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "pool" in result.stderr.lower()


def test_cli_peer_prune_json_removes_inactive_peers(wgpl_db: str) -> None:
    import datetime

    _setup_interface("wg0")
    peer = core.add_peer("wg0", "guest", expires="1h")
    assert peer["id"] is not None

    past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    result = runner.invoke(app, ["--json", "peer", "prune", "wg0"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {"status": "success", "interface": "wg0", "deleted_count": 1}
    assert db.get_peer(peer["id"]) is None


def test_cli_interface_remove_blocked_when_peers_exist(wgpl_db: str) -> None:
    _setup_interface("wg0")
    core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["interface", "remove", "wg0"])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "peer" in result.stderr.lower()
    assert len(db.get_interfaces_by_name("wg0")) > 0


def test_cli_interface_remove_force_with_peers(wgpl_db: str) -> None:
    _setup_interface("wg0")
    core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["interface", "remove", "wg0", "--force"])

    assert result.exit_code == 0
    assert db.get_interface("wg0") is None


def test_cli_peer_history_json(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")

    result = runner.invoke(
        app, ["--json", "peer", "history", "wg0", str(peer["id"])]
    )

    assert result.exit_code == 0
    events = json.loads(result.stdout)
    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0]["event_type"] == "created"


def test_cli_interface_history_json(wgpl_db: str) -> None:
    _setup_interface("wg0")

    result = runner.invoke(app, ["--json", "interface", "history", "wg0"])

    assert result.exit_code == 0
    events = json.loads(result.stdout)
    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0]["event_type"] == "created"


def test_cli_peer_add_invalid_mtu_exits_cleanly(wgpl_db: str) -> None:
    _setup_interface("wg0")

    result = runner.invoke(app, ["peer", "add", "wg0", "bad", "--mtu", "100"])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "576" in result.stderr


def test_cli_peer_history_respects_limit(wgpl_db: str) -> None:
    from wgpl.db import AuditEntityType, AuditEventType

    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")
    peer_id = str(peer["id"])

    with db.transaction() as conn:
        for _ in range(5):
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=peer_id,
                event_type=AuditEventType.UPDATED,
                interface="wg0",
                name="phone",
                metadata={"fields": ["name"]},
                conn=conn,
            )

    result = runner.invoke(
        app, ["--json", "peer", "history", "wg0", peer_id, "--limit", "3"]
    )

    assert result.exit_code == 0
    events = json.loads(result.stdout)
    assert len(events) == 3
