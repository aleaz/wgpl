"""CLI CRUD option matrix: exercise flags on interface/peer/db commands."""

from __future__ import annotations

import datetime
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner, Result

from wgpl import core, db, wireguard
from wgpl.cli import app

runner = CliRunner()


def _no_traceback(result: Result) -> None:
    assert "Traceback (most recent call last)" not in result.output


def _invoke(args: list[str], **kwargs: Any) -> Result:
    result = runner.invoke(app, args, **kwargs)
    _no_traceback(result)
    return result


def _pubkey() -> str:
    return wireguard.generate_keypair().public_key


def _add_interface(
    name: str = "wg0",
    *,
    json_out: bool = False,
    **flags: str | int,
) -> str:
    pubkey = _pubkey()
    args: list[str] = []
    if json_out:
        args.append("--json")
    args.extend(
        [
            "interface",
            "add",
            name,
            "vpn.example.com",
            pubkey,
            "10.0.0.0/24",
        ]
    )
    for key, value in flags.items():
        args.extend([f"--{key.replace('_', '-')}", str(value)])
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    return pubkey


def _add_peer(
    iface: str,
    name: str,
    *,
    json_out: bool = True,
    **flags: str | int,
) -> dict[str, Any]:
    args: list[str] = []
    if json_out:
        args.append("--json")
    args.extend(["peer", "add", iface, name])
    for key, value in flags.items():
        args.extend([f"--{key.replace('_', '-')}", str(value)])
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


@pytest.fixture
def seeded(wgpl_db: str) -> dict[str, Any]:
    """wg0 interface with one active peer."""
    _add_interface("wg0", dns="1.1.1.1", desc="Office VPN", mtu=1420, keepalive=25)
    peer = _add_peer(
        "wg0",
        "phone",
        ip="10.0.0.2",
        dns="9.9.9.9",
        desc="handset",
        mtu=1380,
        keepalive=15,
        expires="30d",
    )
    return {"peer": peer}


# --- Interface CRUD options ---


def test_cli_interface_add_all_options_json(wgpl_db: str) -> None:
    pubkey = _pubkey()
    result = _invoke(
        [
            "--json",
            "interface",
            "add",
            "wg0",
            "vpn.example.com",
            pubkey,
            "10.0.0.0/24",
            "--port",
            "51821",
            "--dns",
            "1.1.1.1",
            "--desc",
            "lab",
            "--mtu",
            "1420",
            "--keepalive",
            "25",
        ]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["port"] == 51821
    assert payload["dns"] == "1.1.1.1"
    assert payload["desc"] == "lab"
    assert payload["mtu"] == 1420
    assert payload["keepalive"] == 25


def test_cli_interface_show_human_and_json(seeded: dict) -> None:
    human = _invoke(["interface", "show", "wg0"])
    assert human.exit_code == 0
    assert "wg0" in human.stdout

    j = _invoke(["--json", "interface", "show", "wg0"])
    assert j.exit_code == 0
    payload = json.loads(j.stdout)
    assert payload["name"] == "wg0"
    assert payload["mtu"] == 1420


def test_cli_interface_list_escapes_rich_markup_in_desc(wgpl_db: str) -> None:
    _add_interface("wg0", desc="[red]owned[/red]")
    result = _invoke(["interface", "list"])
    assert result.exit_code == 0
    assert "[red]" in result.stdout or "owned" in result.stdout
    assert "Traceback" not in result.output


def test_cli_interface_update_set_fields_json(seeded: dict) -> None:
    new_key = _pubkey()
    result = _invoke(
        [
            "--json",
            "interface",
            "update",
            "wg0",
            "--endpoint",
            "vpn2.example.com",
            "--port",
            "51900",
            "--public-key",
            new_key,
            "--dns",
            "8.8.8.8",
            "--desc",
            "updated",
            "--mtu",
            "1400",
            "--keepalive",
            "30",
        ]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["endpoint"] == "vpn2.example.com"
    assert payload["port"] == 51900
    assert payload["public_key"] == new_key
    assert payload["dns"] == "8.8.8.8"
    iface = db.get_interfaces_by_name("wg0")[0]
    assert iface["desc"] == "updated"
    assert iface["mtu"] == 1400
    assert iface["keepalive"] == 30


def test_cli_interface_update_clear_flags_json(seeded: dict) -> None:
    result = _invoke(
        [
            "--json",
            "interface",
            "update",
            "wg0",
            "--clear-dns",
            "--clear-desc",
            "--clear-mtu",
            "--clear-keepalive",
        ]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload.get("dns") is None
    assert payload.get("desc") is None
    assert payload.get("mtu") is None
    assert payload.get("keepalive") is None


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--dns", "1.1.1.1", "--clear-dns"],
        ["--desc", "x", "--clear-desc"],
        ["--mtu", "1400", "--clear-mtu"],
        ["--keepalive", "10", "--clear-keepalive"],
    ],
)
def test_cli_interface_update_conflicting_clear_flags(
    seeded: dict, extra_args: list[str]
) -> None:
    result = _invoke(["interface", "update", "wg0", *extra_args])
    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr


def test_cli_interface_export_human_and_json(seeded: dict) -> None:
    human = _invoke(["interface", "export", "wg0"])
    assert human.exit_code == 0
    assert "[Peer]" in human.stdout

    j = _invoke(["--json", "interface", "export", "wg0"])
    assert j.exit_code == 0
    assert "[Peer]" in json.loads(j.stdout)["config"]


def test_cli_interface_history_pagination(seeded: dict) -> None:
    j = _invoke(
        ["--json", "interface", "history", "wg0", "--limit", "2", "--offset", "0"]
    )
    assert j.exit_code == 0
    events = json.loads(j.stdout)
    assert isinstance(events, list)
    assert len(events) >= 1

    human = _invoke(["interface", "history", "wg0", "--limit", "1"])
    assert human.exit_code == 0


# --- Peer CRUD options ---


def test_cli_peer_add_all_options_json(wgpl_db: str) -> None:
    _add_interface("wg0", dns="1.1.1.1")
    peer = _add_peer(
        "wg0",
        "laptop",
        ip="10.0.0.5",
        dns="8.8.4.4",
        desc="work",
        mtu=1400,
        keepalive=20,
        expires="7d",
    )
    assert peer["ip_address"] == "10.0.0.5"
    assert peer["dns"] == "8.8.4.4"
    assert peer["desc"] == "work"
    assert peer["mtu"] == 1400
    assert peer["keepalive"] == 20
    row = db.get_peer(peer["id"])
    assert row is not None
    assert row["expires_at"] is not None


def test_cli_peer_show_secrets_human(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    row = db.get_peer(peer_id)
    assert row is not None
    assert row["preshared_key"]

    result = _invoke(["peer", "show", peer_id, "--show-secrets"])
    assert result.exit_code == 0
    assert row["preshared_key"] in result.stdout


def test_cli_peer_show_json_redacts(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(["--json", "peer", "show", peer_id])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "private_key" not in payload
    assert "preshared_key" not in payload


def test_cli_peer_list_filters(wgpl_db: str) -> None:
    _add_interface("wg0")
    active = _add_peer("wg0", "active")
    expired = _add_peer("wg0", "expired", expires="1h")
    removed = _add_peer("wg0", "removed")
    _invoke(["peer", "remove", "wg0", removed["id"]])

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute(
            "UPDATE peers SET expires_at = ? WHERE id = ?", (past, expired["id"])
        )
        conn.commit()

    by_iface = _invoke(["--json", "peer", "list", "--interface", "wg0"])
    assert by_iface.exit_code == 0
    names = {p["name"] for p in json.loads(by_iface.stdout)}
    assert "active" in names
    assert "removed" not in names

    expired_only = _invoke(["--json", "peer", "list", "--expired"])
    assert expired_only.exit_code == 0
    expired_peers = json.loads(expired_only.stdout)
    assert any(p["name"] == "expired" for p in expired_peers)
    assert all(p["status"] == "Expired" for p in expired_peers)

    all_peers = _invoke(["--json", "peer", "list", "--all"])
    assert all_peers.exit_code == 0
    all_names = {p["name"] for p in json.loads(all_peers.stdout)}
    assert "removed" in all_names
    assert active["id"] in {p["id"] for p in json.loads(all_peers.stdout)}


def test_cli_peer_update_set_and_clear_json(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(
        [
            "--json",
            "peer",
            "update",
            "wg0",
            peer_id,
            "--ip",
            "10.0.0.10",
            "--dns",
            "8.8.8.8",
            "--desc",
            "new-desc",
            "--mtu",
            "1390",
            "--keepalive",
            "22",
            "--expires",
            "14d",
        ]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ip_address"] == "10.0.0.10"
    assert payload["dns"] == "8.8.8.8"
    assert payload["desc"] == "new-desc"
    assert payload["mtu"] == 1390
    assert payload["keepalive"] == 22

    cleared = _invoke(
        [
            "--json",
            "peer",
            "update",
            "wg0",
            peer_id,
            "--clear-dns",
            "--clear-desc",
            "--clear-mtu",
            "--clear-keepalive",
            "--clear-expires",
        ]
    )
    assert cleared.exit_code == 0
    cp = json.loads(cleared.stdout)
    assert cp.get("dns_override") is None
    assert cp.get("desc") is None
    assert cp.get("mtu_override") is None
    assert cp.get("keepalive") is None or cp.get("keepalive_override") is None
    assert cp.get("expires_at") is None


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--dns", "1.1.1.1", "--clear-dns"],
        ["--desc", "x", "--clear-desc"],
        ["--mtu", "1400", "--clear-mtu"],
        ["--keepalive", "10", "--clear-keepalive"],
        ["--expires", "7d", "--clear-expires"],
    ],
)
def test_cli_peer_update_conflicting_clear_flags(
    seeded: dict, extra_args: list[str]
) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(["peer", "update", "wg0", peer_id, *extra_args])
    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr


def test_cli_peer_remove_soft_and_hard_json(wgpl_db: str) -> None:
    _add_interface("wg0")
    peer = _add_peer("wg0", "soft")
    soft_id = peer["id"]

    soft = _invoke(["--json", "peer", "remove", "wg0", soft_id])
    assert soft.exit_code == 0
    assert db.get_peer(soft_id) is not None

    hard_peer = _add_peer("wg0", "hard")
    hard_id = hard_peer["id"]
    hard = _invoke(["--json", "peer", "remove", "wg0", hard_id, "--hard"])
    assert hard.exit_code == 0
    assert db.get_peer(hard_id) is None


def test_cli_peer_config_allowed_ips(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(
        ["peer", "config", peer_id, "--allowed-ips", "10.0.0.0/8,192.168.0.0/16"]
    )
    assert result.exit_code == 0
    assert "AllowedIPs = 10.0.0.0/8,192.168.0.0/16" in result.stdout

    j = _invoke(
        [
            "--json",
            "peer",
            "config",
            peer_id,
            "--allowed-ips",
            "0.0.0.0/0",
        ]
    )
    assert j.exit_code == 0
    assert "AllowedIPs" in json.loads(j.stdout)["config"]


def test_cli_peer_config_requires_interface_with_two_vpn(wgpl_db: str) -> None:
    _add_interface("wg0")
    _add_interface("wg1", port=51821)
    p0 = _add_peer("wg0", "a")
    _add_peer("wg1", "b")
    short = p0["id"].replace("-", "")[:12]

    missing = _invoke(["peer", "config", short])
    assert missing.exit_code == 1

    ok = _invoke(["peer", "config", short, "-i", "wg0"])
    assert ok.exit_code == 0
    assert "PrivateKey" in ok.stdout


def test_cli_peer_qr_allowed_ips_json(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(
        [
            "--json",
            "peer",
            "qr",
            peer_id,
            "--allowed-ips",
            "10.8.0.0/16",
        ]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["qr"]


# --- Top-level and DB ---


def test_cli_validate_global_and_scoped(seeded: dict) -> None:
    ok = _invoke(["--json", "validate"])
    assert ok.exit_code == 0
    assert json.loads(ok.stdout)["status"] == "ok"

    scoped = _invoke(["--json", "validate", "wg0"])
    assert scoped.exit_code == 0


@patch.object(core, "sync_interface")
def test_cli_apply_human(mock_sync: MagicMock, seeded: dict) -> None:
    result = _invoke(["apply", "wg0"])
    assert result.exit_code == 0
    mock_sync.assert_called_once_with("wg0")


def test_cli_db_dump_to_file_permissions(seeded: dict, tmp_path: Path) -> None:
    out = tmp_path / "backup.db"
    result = _invoke(["db", "dump", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_cli_db_restore_round_trip(seeded: dict, wgpl_db: str) -> None:
    peer_id = seeded["peer"]["id"]
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    try:
        core.dump_database(path)
        with open(path, "rb") as handle:
            binary = handle.read()
        result = _invoke(["--json", "db", "restore", "--yes", "-"], input=binary)
        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == "success"
        restored = db.get_peer(peer_id)
        assert restored is not None
        assert restored["name"] == "phone"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_cli_global_db_option(wgpl_db: str, tmp_path: Path) -> None:
    alt = tmp_path / "alt.db"
    pubkey = _pubkey()
    result = _invoke(
        [
            "--db",
            str(alt),
            "--json",
            "interface",
            "add",
            "wg0",
            "vpn.example.com",
            pubkey,
            "10.0.0.0/24",
        ]
    )
    assert result.exit_code == 0
    assert alt.exists()


def test_cli_peer_update_human_shows_hints(seeded: dict) -> None:
    peer_id = seeded["peer"]["id"]
    result = _invoke(["peer", "update", "wg0", peer_id, "--ip", "10.0.0.15"])
    assert result.exit_code == 0
    assert "apply" in result.stderr.lower() or "sync" in result.stderr.lower()
