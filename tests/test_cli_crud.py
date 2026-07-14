import json
import re
import sys
import datetime

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


def test_cli_validate_escapes_markup_in_issue_detail(wgpl_db: str) -> None:
    _setup_interface()
    with db.get_db() as conn:
        conn.execute(
            "UPDATE interfaces SET endpoint = ? WHERE name = ?",
            ("[red]owned[/red]", "wg0"),
        )
        conn.commit()

    result = runner.invoke(app, ["validate", "wg0"])

    assert result.exit_code == 1
    assert "[red]" in result.stderr


def test_cli_exit_error_escapes_markup(wgpl_db: str) -> None:
    _setup_interface()
    result = runner.invoke(app, ["peer", "show", "[red]missing[/red]"])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "[red]" in result.stderr


def test_cli_interface_update_no_fields(wgpl_db: str) -> None:
    _setup_interface()

    result = runner.invoke(app, ["interface", "update", "wg0"])

    assert result.exit_code == 1


def test_cli_peer_update_ip_hints_on_stderr(wgpl_db: str) -> None:
    _setup_interface()
    peer = json.loads(runner.invoke(app, ["--json", "peer", "add", "-i", "wg0", "p"]).stdout)["data"]

    result = runner.invoke(
        app, ["peer", "update", "-i", "wg0", peer["id"], "--ip", "10.0.0.50"]
    )

    assert result.exit_code == 0
    assert "apply" in result.stderr.lower() or "sync" in result.stderr.lower()


def test_cli_peer_remove_already_deleted_raises_not_found(wgpl_db: str) -> None:
    _setup_interface()
    peer = core.add_peer("wg0", "phone")
    assert peer["id"] is not None

    first = runner.invoke(app, ["peer", "remove", "-i", "wg0", peer["id"]])
    assert first.exit_code == 0

    second = runner.invoke(app, ["peer", "remove", "-i", "wg0", peer["id"]])
    assert second.exit_code == 0
    assert "Soft-deleted peer" in second.stderr


def test_cli_help_skips_database_open(
    wgpl_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Subcommand --help must not require a readable database."""
    monkeypatch.setenv("WGPL_DB_PATH", "/root/forbidden-wgpl.db")
    # CliRunner does not rewrite sys.argv; the CLI checks argv for --help.
    monkeypatch.setattr(sys, "argv", ["wgpl", "peer", "add", "--help"])
    result = runner.invoke(app, ["peer", "add", "--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout or "help" in result.stdout.lower()


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
        lambda ref, iface=None, access=None, policy=None: peer["id"],
    )

    assert peer["id"] is not None
    result = runner.invoke(app, ["peer", "remove", "-i", "wg1", peer["id"]])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "does not belong" in result.stderr
    assert "Unexpected Error" not in result.stderr


def test_cli_interface_port_conflict(wgpl_db: str) -> None:
    _setup_interface("wg0")
    pubkey = wireguard.generate_keypair().public_key

    result = runner.invoke(
        app,
        [
            "interface",
            "add",
            "wg1",
            "vpn.example.com",
            pubkey,
            "10.0.1.0/24",
            "--port",
            "51820",
        ],
    )

    assert result.exit_code == 0


def test_cli_interface_pool_conflict(wgpl_db: str) -> None:
    _setup_interface("wg0")
    pubkey = wireguard.generate_keypair().public_key

    result = runner.invoke(
        app,
        [
            "interface",
            "add",
            "wg1",
            "vpn.example.com",
            pubkey,
            "10.0.0.0/24",
            "--port",
            "51821",
        ],
    )

    assert result.exit_code == 0


def test_cli_interface_update_pool_rejected(wgpl_db: str) -> None:
    _setup_interface("wg0")
    runner.invoke(app, ["peer", "add", "-i", "wg0", "high", "--ip", "10.0.0.200"])

    result = runner.invoke(
        app,
        ["interface", "update", "wg0", "--address-pool", "10.0.0.0/25"],
    )

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "pool" in result.stderr.lower()


def test_cli_peer_prune_json_removes_inactive_peers(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "guest", expires="1h")
    assert peer["id"] is not None

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()

    result = runner.invoke(app, ["--json", "peer", "prune", "-i", "wg0"])

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
    assert not db.get_interfaces_by_name("wg0")


def test_cli_peer_history_json(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["--json", "peer", "history", "-i", "wg0", str(peer["id"])])

    assert result.exit_code == 0
    events = json.loads(result.stdout)["data"]
    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0]["event_type"] == "created"


def test_cli_interface_history_json(wgpl_db: str) -> None:
    _setup_interface("wg0")

    result = runner.invoke(app, ["--json", "interface", "history", "wg0"])

    assert result.exit_code == 0
    events = json.loads(result.stdout)["data"]
    assert isinstance(events, list)
    assert len(events) >= 1
    assert events[0]["event_type"] == "created"


def test_cli_peer_add_invalid_mtu_exits_cleanly(wgpl_db: str) -> None:
    _setup_interface("wg0")

    result = runner.invoke(app, ["peer", "add", "-i", "wg0", "bad", "--mtu", "100"])

    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "1280" in result.stderr


def test_cli_peer_add_single_arg_hints_usage_when_interface_unknown(
    wgpl_db: str,
) -> None:
    result = runner.invoke(app, ["peer", "add", "Alice"])

    assert result.exit_code == 2
    # Rich may insert ANSI between the two dashes of --interface when color is on.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    output = " ".join(plain.lower().split())
    assert "missing option '--interface'" in output or "missing parameter '--interface'" in output


def test_cli_peer_add_unknown_interface_flag_hints_usage(wgpl_db: str) -> None:
    result = runner.invoke(app, ["peer", "add", "-i", "Alice"])

    assert result.exit_code == 1
    stderr = " ".join(result.stderr.split())
    assert "not a known interface" in stderr
    assert "wgpl peer add <NAME> -i <INTERFACE>" in stderr


def test_cli_peer_add_missing_name_keeps_exact_one_message(wgpl_db: str) -> None:
    _setup_interface("wg0")

    result = runner.invoke(app, ["peer", "add", "-i", "wg0"])

    assert result.exit_code == 1
    assert "exactly one" in result.stderr.lower()
    assert "not a known interface" not in result.stderr


def test_cli_peer_config_warns_private_keys_on_stderr(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["peer", "config", peer["id"]])

    assert result.exit_code == 0
    assert "PrivateKey" in result.stdout
    assert "contains private keys" in result.stderr
    assert "PrivateKey" not in result.stderr


def test_cli_peer_config_json_skips_private_key_warning(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["--json", "peer", "config", peer["id"]])

    assert result.exit_code == 0
    assert "contains private keys" not in result.stderr
    payload = json.loads(result.stdout)["data"]
    assert "PrivateKey" in payload["config"]


def test_cli_peer_qr_warns_private_keys_on_stderr(wgpl_db: str) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")

    result = runner.invoke(app, ["peer", "qr", peer["id"]])

    assert result.exit_code == 0
    assert result.stdout.strip()
    assert "contains private keys" in result.stderr


def test_cli_peer_config_wrong_interface_prefix_reports_mismatch(
    wgpl_db: str,
) -> None:
    _setup_interface("wg0")
    peer = core.add_peer("wg0", "phone")
    pubkey = wireguard.generate_keypair().public_key
    runner.invoke(
        app,
        ["interface", "add", "wg1", "vpn2.example.com", pubkey, "10.0.1.0/24"],
    )
    prefix = str(peer["id"]).replace("-", "")[:12]

    result = runner.invoke(
        app, ["peer", "config", prefix, "--interface", "wg1"]
    )

    assert result.exit_code == 1
    assert "does not belong" in result.stderr
    assert "not found" not in result.stderr.lower()


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
        app, ["--json", "peer", "history", "-i", "wg0", peer_id, "--limit", "3"]
    )

    assert result.exit_code == 0
    events = json.loads(result.stdout)["data"]
    assert len(events) == 3
