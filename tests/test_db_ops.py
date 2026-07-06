import glob
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from wgpl import core, db, wireguard
from wgpl.exceptions import WgplException


@pytest.fixture
def valid_backup_path(tmp_path: Path) -> str:
    path = str(tmp_path / "valid_backup.db")
    public_key = wireguard.generate_keypair().public_key
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
        CREATE TABLE IF NOT EXISTS "interfaces" (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, endpoint TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 51820, public_key TEXT NOT NULL,
            address_pool TEXT NOT NULL, dns TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER,
            UNIQUE(name, endpoint, port)
        );
        """
        )
        conn.execute(
            """
        CREATE TABLE IF NOT EXISTS "peers" (
            id TEXT PRIMARY KEY, interface_id INTEGER NOT NULL,
            name TEXT NOT NULL, ip_address TEXT NOT NULL,
            public_key TEXT NOT NULL, private_key TEXT NOT NULL,
            preshared_key TEXT, created_at TEXT NOT NULL, dns TEXT,
            deleted_at TEXT, expires_at TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER,
            FOREIGN KEY(interface_id) REFERENCES interfaces(id) ON DELETE CASCADE
        );
        """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_ip ON peers(interface_id, ip_address) WHERE deleted_at IS NULL;"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_name ON peers(interface_id, name) WHERE deleted_at IS NULL;"
        )
        conn.execute(
            """
        CREATE TABLE IF NOT EXISTS audit_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type  TEXT NOT NULL CHECK(entity_type IN ('peer', 'interface')),
            entity_id    TEXT NOT NULL,
            interface    TEXT,
            event_type   TEXT NOT NULL CHECK(event_type IN ('created', 'updated', 'removed', 'reclaimed', 'pruned', 'cascade_removed')),
            occurred_at  TEXT NOT NULL,
            actor        TEXT,
            name         TEXT,
            ip_address   TEXT,
            public_key   TEXT,
            metadata     TEXT
        );
        """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_events(entity_type, entity_id);"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_interface ON audit_events(interface, occurred_at);"
        )
        conn.execute(
            "INSERT INTO \"interfaces\" VALUES(1, 'wg0','vpn.example.com',51820,?,"
            "'10.0.0.0/24',NULL,NULL,NULL,NULL);",
            (public_key,),
        )
        conn.commit()
    finally:
        conn.close()
    return path


def test_dump_database(wg0_interface: str, tmp_path: Path) -> None:
    path = str(tmp_path / "backup.db")
    core.dump_database(path)
    assert os.path.exists(path)
    conn = sqlite3.connect(path)
    try:
        cursor = conn.execute("SELECT name FROM interfaces WHERE name = 'wg0'")
        assert cursor.fetchone()[0] == "wg0"
    finally:
        conn.close()


def test_restore_database_success(wgpl_db: str, valid_backup_path: str) -> None:
    core.restore_database(valid_backup_path)

    conn = sqlite3.connect(wgpl_db)
    try:
        cursor = conn.execute("SELECT name FROM interfaces WHERE name = 'wg0'")
        assert cursor.fetchone() is not None
    finally:
        conn.close()


def test_restore_database_failure_invalid_syntax(wgpl_db: str, tmp_path: Path) -> None:
    bad_path = str(tmp_path / "bad.db")
    with open(bad_path, "w") as f:
        f.write("This is not a sqlite database")

    with pytest.raises(WgplException, match="not a database"):
        core.restore_database(bad_path)


def test_restore_backup_has_secure_permissions(
    wg0_interface: str, wgpl_db: str, valid_backup_path: str
) -> None:
    core.restore_database(valid_backup_path)

    backups = glob.glob(f"{wgpl_db}.bak.*")
    assert len(backups) > 0
    backup_file = backups[0]

    st = os.stat(backup_file)
    assert stat.S_IMODE(st.st_mode) == 0o600


def test_restore_rejects_missing_schema(wgpl_db: str, tmp_path: Path) -> None:
    bad_path = str(tmp_path / "bad.db")
    conn = sqlite3.connect(bad_path)
    try:
        conn.execute("CREATE TABLE wrong_table (id INTEGER);")
    finally:
        conn.close()

    with pytest.raises(
        WgplException, match="Restored database is missing required tables"
    ):
        core.restore_database(bad_path)


def test_restore_no_tmp_wal_leftover(
    wg0_interface: str, wgpl_db: str, valid_backup_path: str
) -> None:
    core.restore_database(valid_backup_path)
    tmp_path = f"{wgpl_db}.tmp"
    assert not os.path.exists(tmp_path)
    assert not os.path.exists(f"{tmp_path}-wal")
    assert not os.path.exists(f"{tmp_path}-shm")


def test_restore_returns_warnings_list(
    wg0_interface: str, valid_backup_path: str
) -> None:
    warnings = core.restore_database(valid_backup_path)
    assert isinstance(warnings, list)


def test_dump_restore_roundtrip_preserves_peers_and_audit(
    wg0_interface: str, tmp_path: Path
) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.3")
    peer_id = str(peer["id"])

    backup_file = str(tmp_path / "roundtrip.db")
    core.dump_database(backup_file)

    core.remove_peer(wg0_interface, peer_id, hard=True)

    core.restore_database(backup_file)

    with db.get_db() as conn:
        restored_peer = db.get_peer(peer_id, conn=conn)
        assert restored_peer is not None

        cursor = conn.execute(
            "SELECT COUNT(*) FROM audit_events WHERE entity_id = ?", (peer_id,)
        )
        count = cursor.fetchone()[0]
        assert count > 0


def test_restore_rotates_backups(
    wg0_interface: str, wgpl_db: str, valid_backup_path: str
) -> None:
    for i in range(5):
        core.restore_database(valid_backup_path)

    backups = glob.glob(f"{wgpl_db}.bak.*")
    assert len(backups) == 3


def test_restore_init_db_failure_cleans_tmp(
    monkeypatch: pytest.MonkeyPatch,
    wgpl_db: str,
    tmp_path: Path,
    valid_backup_path: str,
) -> None:
    def fake_init() -> None:
        raise sqlite3.OperationalError("Simulated failure")

    monkeypatch.setattr("wgpl.db.init_db", fake_init)

    with pytest.raises(Exception, match="Simulated failure"):
        core.restore_database(valid_backup_path)

    tmp_path_db = f"{wgpl_db}.tmp"
    assert not os.path.exists(tmp_path_db)


def test_restore_retry_after_leftover_tmp(wgpl_db: str, valid_backup_path: str) -> None:
    tmp_path = f"{wgpl_db}.tmp"
    with open(tmp_path, "w") as f:
        f.write("leftover")

    core.restore_database(valid_backup_path)
    assert not os.path.exists(tmp_path)


def test_restore_rename_failure_preserves_live_db(
    wg0_interface: str,
    wgpl_db: str,
    monkeypatch: pytest.MonkeyPatch,
    valid_backup_path: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    def fail_rename(src: str, dst: str) -> None:
        if src.endswith(".tmp"):
            raise OSError("rename blocked")

    monkeypatch.setattr(os, "rename", fail_rename)

    with pytest.raises(OSError, match="rename blocked"):
        core.restore_database(valid_backup_path)

    restored_peer = db.get_peer(peer_id)
    assert restored_peer is not None
