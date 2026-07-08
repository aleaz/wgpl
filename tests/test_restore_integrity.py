import os
import sqlite3
import stat
from pathlib import Path

import pytest

from wgpl import core, db
from wgpl.exceptions import WgplException


def test_dump_database_secure_permissions(wg0_interface: str, tmp_path: Path) -> None:
    path = str(tmp_path / "backup.db")
    core.dump_database(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_restore_rejects_malformed_wire_fields(
    wg0_interface: str, tmp_path: Path
) -> None:
    core.add_peer(wg0_interface, "phone")
    backup = str(tmp_path / "bad.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute(
            "UPDATE peers SET public_key = ? WHERE node_id = "
            "(SELECT id FROM nodes WHERE name = 'phone')",
            ("AAAA\nINJECT",),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Restored database failed validation"):
        core.restore_database(backup)


def test_restore_reinstalls_audit_immutability_triggers(
    wg0_interface: str, tmp_path: Path
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("DROP TRIGGER IF EXISTS trg_audit_immutable_delete")
        conn.execute(
            """
            CREATE TRIGGER trg_audit_immutable_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT 1;
            END;
            """
        )
        conn.commit()
    finally:
        conn.close()

    core.restore_database(backup)

    with db.get_db() as conn:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE entity_id = ?", (peer_id,)
        )
        assert cursor.fetchone()[0] > 0
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            conn.execute("DELETE FROM audit_events WHERE entity_id = ?", (peer_id,))


def test_restore_rejects_unsupported_schema_version(
    wg0_interface: str, tmp_path: Path
) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("PRAGMA user_version = 99")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Unsupported schema version"):
        core.restore_database(backup)


def test_restore_rejects_missing_audit_triggers(
    wg0_interface: str, tmp_path: Path
) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("DROP TRIGGER IF EXISTS trg_audit_immutable_update")
        conn.execute("DROP TRIGGER IF EXISTS trg_audit_immutable_delete")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Missing required triggers"):
        core.restore_database(backup)


def test_restore_rejects_extra_index(wg0_interface: str, tmp_path: Path) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("CREATE INDEX evil_idx ON peers(ip_address)")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Unauthorized indexes"):
        core.restore_database(backup)


def test_restore_rejects_extra_trigger(wg0_interface: str, tmp_path: Path) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute(
            """
            CREATE TRIGGER trg_malicious_insert
            AFTER INSERT ON peers
            BEGIN
                SELECT 1;
            END;
            """
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Unauthorized triggers"):
        core.restore_database(backup)


def test_restore_rejects_extra_table(wg0_interface: str, tmp_path: Path) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("CREATE TABLE evil (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Unauthorized tables"):
        core.restore_database(backup)


def test_restore_rejects_extra_view(wg0_interface: str, tmp_path: Path) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("CREATE VIEW peer_secrets AS SELECT private_key FROM peers")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Unauthorized views"):
        core.restore_database(backup)


def test_restore_rejects_invalid_mtu(wg0_interface: str, tmp_path: Path) -> None:
    backup = str(tmp_path / "backup.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute("UPDATE interfaces SET mtu = ? WHERE name = 'wg0'", (100,))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Restored database failed validation"):
        core.restore_database(backup)


def test_restore_accepts_warning_only_backup(
    wg0_interface: str, tmp_path: Path
) -> None:
    """A state the CLI can create must be restorable from its own backup.

    A subnet_router without an effective keepalive raises only a
    ``subnet_router_missing_keepalive`` *warning* in ``validate``. Restore must
    not treat warnings as fatal (regression for the QA-found asymmetry between
    the mutation-time gate and the restore-time validation).
    """
    core.add_peer(
        wg0_interface,
        "router",
        role=core.PeerRole.SUBNET_ROUTER,
        routed_networks="192.168.77.0/24",
    )
    backup = str(tmp_path / "warn.db")
    core.dump_database(backup)

    warnings = core.restore_database(backup)
    assert isinstance(warnings, list)

    peers = {p["name"] for p in core.list_peers(wg0_interface)}
    assert "router" in peers


def test_restore_rejects_peer_ip_outside_pool(
    wg0_interface: str, tmp_path: Path
) -> None:
    """Error-severity consistency issues must still fail-closed on restore."""
    core.add_peer(wg0_interface, "phone")
    backup = str(tmp_path / "oob.db")
    core.dump_database(backup)

    conn = sqlite3.connect(backup)
    try:
        conn.execute(
            "UPDATE peers SET ip_address = ? WHERE node_id = "
            "(SELECT id FROM nodes WHERE name = 'phone')",
            ("10.99.0.9",),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(WgplException, match="Restored database failed validation"):
        core.restore_database(backup)
