"""QA matrix: CLI commands across database lifecycle states."""

from __future__ import annotations

import os
import stat
import tempfile

import pytest
from typer.testing import CliRunner

from wgpl import db, wireguard
from wgpl.cli import app

from tests.json_helpers import json_status_payload, json_success_data


runner = CliRunner()

IFACE_PUBKEY = wireguard.generate_keypair().public_key
MISSING_IFACE = "wg0"
MISSING_PEER = "00000000-0000-0000-0000-000000000001"
MISSING_NODE = "ghostnode"


def _no_traceback(result: object) -> None:
    """Assert the CLI did not emit a Python traceback."""
    output = getattr(result, "output", "")
    assert "Traceback (most recent call last)" not in output


@pytest.fixture
def fresh_db_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """S1: database file path that does not exist yet."""
    path = os.path.join(tempfile.mkdtemp(), "fresh.db")
    assert not os.path.exists(path)
    monkeypatch.setenv("WGPL_DB_PATH", path)
    return path


@pytest.fixture
def empty_db_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """S2: initialized schema with no interfaces or peers."""
    path = os.path.join(tempfile.mkdtemp(), "empty.db")
    monkeypatch.setenv("WGPL_DB_PATH", path)
    db.init_db(path)
    return path


@pytest.fixture
def bad_db_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """S4: parent directory does not exist."""
    path = os.path.join(tempfile.mkdtemp(), "missing", "nested", "w.db")
    monkeypatch.setenv("WGPL_DB_PATH", path)
    return path


@pytest.fixture
def corrupt_db_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """S5: path exists but is not a valid SQLite database."""
    path = os.path.join(tempfile.mkdtemp(), "corrupt.db")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("NOT A SQLITE DATABASE\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv("WGPL_DB_PATH", path)
    return path


def _iface_add_args() -> list[str]:
    return [
        "interface",
        "add",
        MISSING_IFACE,
        "vpn.example.com",
        IFACE_PUBKEY,
        "10.0.0.0/24",
    ]


# --- S1 / S2: healthy database states ---


@pytest.mark.parametrize(
    "command",
    [
        ["validate"],
        ["db", "dump"],
    ],
)
def test_read_commands_on_fresh_db_initializes(
    fresh_db_path: str,
    command: list[str],
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == 0
    assert os.path.exists(fresh_db_path)


@pytest.mark.parametrize(
    "command",
    [
        ["interface", "list"],
        ["peer", "list"],
    ],
)
def test_readonly_commands_on_fresh_db_fail_without_init(
    fresh_db_path: str,
    command: list[str],
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == 1
    assert not os.path.exists(fresh_db_path)


@pytest.mark.parametrize(
    "command,expected_code",
    [
        (["validate"], 0),
        (["interface", "list"], 0),
        (["peer", "list"], 0),
        (["db", "dump"], 0),
    ],
)
def test_read_commands_on_empty_db(
    empty_db_path: str,
    command: list[str],
    expected_code: int,
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == expected_code


def test_validate_fresh_db_json(fresh_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "validate"])
    _no_traceback(result)
    assert result.exit_code == 0
    assert json_status_payload(result) == {"status": "ok", "issues": []}


def test_interface_list_empty_db_shows_message(empty_db_path: str) -> None:
    result = runner.invoke(app, ["interface", "list"])
    _no_traceback(result)
    assert result.exit_code == 0
    assert "No interfaces found" in result.stderr


def test_peer_list_empty_db_shows_message(empty_db_path: str) -> None:
    result = runner.invoke(app, ["peer", "list"])
    _no_traceback(result)
    assert result.exit_code == 0
    assert "No peers found" in result.stderr


def test_interface_list_empty_db_json(empty_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "interface", "list"])
    _no_traceback(result)
    assert result.exit_code == 0
    assert json_success_data(result) == []


# --- S3: missing entities on empty DB ---


@pytest.mark.parametrize(
    "command",
    [
        ["validate", MISSING_IFACE],
        ["interface", "remove", MISSING_IFACE],
        ["interface", "export", MISSING_IFACE],
        ["interface", "update", MISSING_IFACE],
        ["peer", "add", "-i", MISSING_IFACE, "phone"],
        ["peer", "remove", "-i", MISSING_IFACE, MISSING_PEER],
        ["peer", "config", MISSING_PEER],
        ["peer", "qr", MISSING_PEER],
        ["peer", "update", "-i", MISSING_IFACE, MISSING_PEER, "--dns", "1.1.1.1"],
        ["peer", "prune", "-i", MISSING_IFACE],
        ["node", "show", MISSING_NODE],
        ["node", "remove", MISSING_NODE],
        ["node", "update", MISSING_NODE, "--name", "renamed"],
        ["apply", MISSING_IFACE],
    ],
)
def test_missing_entity_exits_cleanly(
    empty_db_path: str,
    command: list[str],
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr


def test_validate_missing_interface_json(empty_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "validate", MISSING_IFACE])
    _no_traceback(result)
    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert "not found" in payload["message"].lower()


def test_interface_add_on_fresh_db(fresh_db_path: str) -> None:
    result = runner.invoke(app, _iface_add_args())
    _no_traceback(result)
    assert result.exit_code == 0
    assert os.path.exists(fresh_db_path)


# --- S4 / S5: broken database paths ---


@pytest.mark.parametrize(
    "command",
    [
        ["validate"],
        ["interface", "list"],
        ["peer", "list"],
        ["db", "dump"],
        ["validate", MISSING_IFACE],
    ],
)
def test_bad_db_path_exits_cleanly(
    bad_db_path: str,
    command: list[str],
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr
    assert "does not exist" in result.stderr.lower()


@pytest.mark.parametrize(
    "command",
    [
        ["validate"],
        ["interface", "list"],
        ["peer", "list"],
        ["db", "dump"],
    ],
)
def test_corrupt_db_exits_cleanly(
    corrupt_db_path: str,
    command: list[str],
) -> None:
    result = runner.invoke(app, command)
    _no_traceback(result)
    assert result.exit_code == 1
    assert "WGPL Error" in result.stderr


def test_bad_db_path_json_error(bad_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "validate"])
    _no_traceback(result)
    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert "directory does not exist" in payload["message"].lower()


def test_corrupt_db_json_error(corrupt_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "validate"])
    _no_traceback(result)
    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert payload["message"]
