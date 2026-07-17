"""QA matrix: CLI commands across database lifecycle states."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import tempfile

import pytest
from typer.testing import CliRunner

from wgpl import core, db, wireguard
from wgpl.cli import app

from tests.json_helpers import json_status_payload, json_success_data


runner = CliRunner()

IFACE_PUBKEY = wireguard.generate_keypair().public_key
MISSING_IFACE = "wg0"
MISSING_PEER = "00000000-0000-0000-0000-000000000001"
MISSING_NODE = "ghostnode"
PROJECTION_COMMANDS = [
    ["interface", "export", MISSING_IFACE],
    ["peer", "config", MISSING_PEER],
    ["peer", "qr", MISSING_PEER],
    ["apply", MISSING_IFACE],
]

_ROW_QUERIES = (
    ("interfaces", "SELECT * FROM interfaces ORDER BY id"),
    ("nodes", "SELECT * FROM nodes ORDER BY id"),
    ("peers", "SELECT * FROM peers ORDER BY id"),
    ("audit_events", "SELECT * FROM audit_events ORDER BY id"),
)


def _database_observation(
    path: str,
) -> tuple[
    bytes,
    tuple[tuple[str, tuple[tuple[object, ...], ...]], ...],
    tuple[tuple[object, ...], ...],
    int,
    tuple[bool, bool],
]:
    database_path = Path(path)
    with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as conn:
        rows = tuple(
            (table, tuple(tuple(row) for row in conn.execute(query).fetchall()))
            for table, query in _ROW_QUERIES
        )
        schema = tuple(
            tuple(row)
            for row in conn.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_schema
                ORDER BY type, name
                """
            ).fetchall()
        )
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])

    return (
        database_path.read_bytes(),
        rows,
        schema,
        user_version,
        (
            Path(f"{database_path}-wal").exists(),
            Path(f"{database_path}-shm").exists(),
        ),
    )


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
        ["db", "doctor"],
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
    assert result.exit_code == 1
    assert not os.path.exists(fresh_db_path)
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert "does not exist" in payload["message"].lower()

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
    assert "database does not exist" in payload["message"].lower()


def test_corrupt_db_json_error(corrupt_db_path: str) -> None:
    result = runner.invoke(app, ["--json", "validate"])
    _no_traceback(result)
    assert result.exit_code == 1
    payload = json_status_payload(result)
    assert payload["status"] == "error"
    assert payload["message"]


@pytest.mark.parametrize("command", PROJECTION_COMMANDS)
@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_projection_commands_on_missing_database(
    fresh_db_path: str,
    command: list[str],
    json_mode: bool,
) -> None:
    args = ["--json", *command] if json_mode else command

    result = runner.invoke(app, args)

    _no_traceback(result)
    assert result.exit_code == 1
    apply_creates_database = command[0] == "apply"
    assert os.path.exists(fresh_db_path) is apply_creates_database
    expected_message = (
        f"Interface {MISSING_IFACE} not found"
        if apply_creates_database
        else f"Database does not exist: {fresh_db_path}"
    )
    expected_stderr = f"WGPL Error: {expected_message}"
    if json_mode:
        payload = json_status_payload(result)
        assert payload == {
            "status": "error",
            "message": expected_message,
        }
        assert " ".join(result.stderr.split()) == expected_stderr
    else:
        assert result.stdout == ""
        assert " ".join(result.stderr.split()) == expected_stderr


@pytest.mark.parametrize("command", PROJECTION_COMMANDS)
@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_projection_commands_reject_corrupt_database(
    corrupt_db_path: str,
    command: list[str],
    json_mode: bool,
) -> None:
    args = ["--json", *command] if json_mode else command

    result = runner.invoke(app, args)

    _no_traceback(result)
    assert result.exit_code == 1
    expected_message = (
        f"Failed to connect to database at {corrupt_db_path}: "
        "file is not a database"
    )
    if json_mode:
        payload = json_status_payload(result)
        assert payload == {"status": "error", "message": expected_message}
        assert " ".join(result.stderr.split()) == f"WGPL Error: {expected_message}"
    else:
        assert result.stdout == ""
        assert " ".join(result.stderr.split()) == f"WGPL Error: {expected_message}"


@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_populated_projection_reads_preserve_database_and_schema(
    wgpl_db: str,
    wg0_interface: str,
    json_mode: bool,
) -> None:
    peer = core.add_peer(wg0_interface, "readonly_projection_peer")
    peer_id = str(peer["id"])
    commands = (
        ["interface", "export", wg0_interface],
        ["peer", "config", peer_id],
        ["peer", "qr", peer_id],
    )

    initial = _database_observation(wgpl_db)
    schema_objects = {(str(row[0]), str(row[1])) for row in initial[2]}
    assert initial[3] == 1
    assert {
        name for object_type, name in schema_objects if object_type == "table"
    } == {
        "audit_events",
        "interfaces",
        "nodes",
        "peers",
        "sqlite_sequence",
    }
    assert {
        name
        for object_type, name in schema_objects
        if object_type == "index" and not name.startswith("sqlite_autoindex_")
    } == {
        "idx_audit_entity",
        "idx_audit_interface",
        "idx_peers_active_ip",
        "idx_peers_active_node",
    }
    assert {
        name for object_type, name in schema_objects if object_type == "trigger"
    } == {
        "trg_audit_immutable_delete",
        "trg_audit_immutable_update",
    }

    for command in commands:
        before = _database_observation(wgpl_db)
        args = ["--json", *command] if json_mode else command
        result = runner.invoke(app, args)
        after = _database_observation(wgpl_db)

        assert result.exit_code == 0
        assert after == before
        assert after == initial


@pytest.mark.parametrize(
    "command",
    [
        ["peer", "config", MISSING_PEER, "--allowed-ips", "not-a-network"],
        ["peer", "qr", MISSING_PEER, "--allowed-ips", "not-a-network"],
    ],
)
@pytest.mark.parametrize("json_mode", [False, True], ids=["human", "json"])
def test_cli_invalid_override_precedes_missing_database(
    fresh_db_path: str,
    command: list[str],
    json_mode: bool,
) -> None:
    args = ["--json", *command] if json_mode else command

    result = runner.invoke(app, args)

    _no_traceback(result)
    assert result.exit_code == 1
    assert not os.path.exists(fresh_db_path)
    expected_message = (
        "Invalid AllowedIPs format 'not-a-network' (WGPL supports IPv4 only)"
    )
    if json_mode:
        assert json_status_payload(result) == {
            "status": "error",
            "message": expected_message,
        }
        assert " ".join(result.stderr.split()) == f"WGPL Error: {expected_message}"
    else:
        assert result.stdout == ""
        assert result.stderr == f"WGPL Error: {expected_message}\n"
