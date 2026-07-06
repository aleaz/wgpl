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
            "UPDATE peers SET public_key = ? WHERE name = 'phone'",
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

    with pytest.raises(WgplException, match="unsupported schema version"):
        core.restore_database(backup)
