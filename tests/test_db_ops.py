import glob
import os
import sqlite3
import stat

import pytest

from wgpl import core, db
from wgpl.exceptions import WgplException

_VALID_RESTORE_SQL = """
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "interfaces" (
    name TEXT PRIMARY KEY, endpoint TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 51820 UNIQUE, public_key TEXT NOT NULL,
    address_pool TEXT NOT NULL UNIQUE, dns TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER
);
CREATE TABLE IF NOT EXISTS "peers" (
    id TEXT PRIMARY KEY, interface TEXT NOT NULL,
    name TEXT NOT NULL, ip_address TEXT NOT NULL,
    public_key TEXT NOT NULL, private_key TEXT NOT NULL,
    preshared_key TEXT, created_at TEXT NOT NULL, dns TEXT,
    deleted_at TEXT, expires_at TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_ip ON peers(interface, ip_address) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_name ON peers(interface, name) WHERE deleted_at IS NULL;
INSERT INTO "interfaces" VALUES('wg0','vpn.example.com',51820,'pubkey','10.0.0.0/24',NULL,NULL,NULL,NULL);
COMMIT;
"""


def test_dump_database_lines(wg0_interface: str) -> None:
    lines = list(core.dump_database_lines())
    output = "".join(lines)

    assert "BEGIN TRANSACTION;" in output
    assert "CREATE TABLE interfaces" in output
    assert "INSERT INTO \"interfaces\" VALUES('wg0'" in output
    assert "COMMIT;" in output


def test_restore_database_success(wgpl_db: str) -> None:
    core.restore_database(_VALID_RESTORE_SQL)

    with sqlite3.connect(wgpl_db) as conn:
        cursor = conn.execute("SELECT name FROM interfaces WHERE name = 'wg0'")
        result = cursor.fetchone()

    assert result is not None
    assert result[0] == "wg0"
    assert not os.path.exists(f"{wgpl_db}.tmp")


def test_restore_database_failure_invalid_syntax(wgpl_db: str) -> None:
    with sqlite3.connect(wgpl_db) as conn:
        conn.execute("CREATE TABLE original (id INT)")

    invalid_sql = "BEGIN TRANSACTION; CREATE TABL ERROR SYNTAX;"

    with pytest.raises(WgplException, match="Failed to restore database"):
        core.restore_database(invalid_sql)

    with sqlite3.connect(wgpl_db) as conn:
        conn.execute("SELECT * FROM original")

    assert not os.path.exists(f"{wgpl_db}.tmp")


def test_restore_backup_has_secure_permissions(wg0_interface: str, wgpl_db: str) -> None:
    """Backup file created during restore must have 0o600 permissions."""
    core.restore_database(_VALID_RESTORE_SQL)

    backups = glob.glob(f"{wgpl_db}.bak.*")
    assert len(backups) == 1
    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600


def test_restore_rejects_missing_schema(wgpl_db: str) -> None:
    """Restore must reject SQL that doesn't create interfaces+peers tables."""
    bad_sql = """
    BEGIN TRANSACTION;
    CREATE TABLE IF NOT EXISTS unrelated (id INTEGER PRIMARY KEY);
    COMMIT;
    """
    with pytest.raises(WgplException, match="missing required tables"):
        core.restore_database(bad_sql)

    assert not os.path.exists(f"{wgpl_db}.tmp")




def test_restore_legacy_sql_creates_audit_table(wgpl_db: str) -> None:
    """Legacy backups without audit_events get the table via init_db after restore."""
    core.restore_database(_VALID_RESTORE_SQL)
    with sqlite3.connect(wgpl_db) as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'"
        )
        assert cursor.fetchone() is not None


def test_restore_no_tmp_wal_leftover(wg0_interface: str, wgpl_db: str) -> None:
    """No tmp, tmp-wal, or tmp-shm files should remain after restore."""
    core.restore_database(_VALID_RESTORE_SQL)

    assert not os.path.exists(f"{wgpl_db}.tmp")
    assert not os.path.exists(f"{wgpl_db}.tmp-wal")
    assert not os.path.exists(f"{wgpl_db}.tmp-shm")


def test_restore_returns_warnings_list(wg0_interface: str) -> None:
    warnings = core.restore_database(_VALID_RESTORE_SQL)
    assert isinstance(warnings, list)


def test_dump_restore_roundtrip_preserves_peers_and_audit(wg0_interface: str, wgpl_db: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.3")
    peer_id = str(peer["id"])
    audit_before = len(db.list_audit_events(limit=1000))
    sql_script = "".join(core.dump_database_lines())

    core.restore_database(sql_script)

    restored_peer = db.get_peer(peer_id)
    assert restored_peer is not None
    assert restored_peer["name"] == "phone"
    assert restored_peer["ip_address"] == "10.0.0.3"
    assert len(db.list_audit_events(limit=1000)) == audit_before
    events = core.list_peer_audit_history(peer_id, wg0_interface)
    assert any(e["event_type"] == "created" for e in events)

_DUPLICATE_ACTIVE_PEER_SQL = """
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "interfaces" (
    name TEXT PRIMARY KEY, endpoint TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 51820 UNIQUE, public_key TEXT NOT NULL,
    address_pool TEXT NOT NULL UNIQUE, dns TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER
);
CREATE TABLE IF NOT EXISTS "peers" (
    id TEXT PRIMARY KEY, interface TEXT NOT NULL,
    name TEXT NOT NULL, ip_address TEXT NOT NULL,
    public_key TEXT NOT NULL, private_key TEXT NOT NULL,
    preshared_key TEXT, created_at TEXT NOT NULL, dns TEXT,
    deleted_at TEXT, expires_at TEXT, desc TEXT, mtu INTEGER, keepalive INTEGER
);
INSERT INTO "interfaces" VALUES('wg0','vpn.example.com',51820,'pubkey','10.0.0.0/24',NULL,NULL,NULL,NULL);
INSERT INTO "peers" VALUES(
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','wg0','a','10.0.0.2',
    'pub1','priv1',NULL,'2020-01-01T00:00:00+00:00',NULL,NULL,NULL,NULL,NULL,NULL
);
INSERT INTO "peers" VALUES(
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','wg0','b','10.0.0.2',
    'pub2','priv2',NULL,'2020-01-01T00:00:00+00:00',NULL,NULL,NULL,NULL,NULL,NULL
);
COMMIT;
"""


def test_restore_rejects_duplicate_active_peers(wgpl_db: str) -> None:
    with sqlite3.connect(wgpl_db) as conn:
        conn.execute("CREATE TABLE marker (id INT)")
        conn.commit()

    with pytest.raises(WgplException, match="failed validation"):
        core.restore_database(_DUPLICATE_ACTIVE_PEER_SQL)

    with sqlite3.connect(wgpl_db) as conn:
        conn.execute("SELECT * FROM marker")
    assert not os.path.exists(f"{wgpl_db}.tmp")


def test_restore_rotates_backups(wg0_interface: str, wgpl_db: str) -> None:
    for _ in range(4):
        core.restore_database(_VALID_RESTORE_SQL)

    backups = glob.glob(f"{wgpl_db}.bak.*")
    assert len(backups) <= 3


def test_restore_init_db_failure_cleans_tmp(monkeypatch: pytest.MonkeyPatch, wgpl_db: str) -> None:
    from wgpl import db as wgpl_db_mod

    def fail_init(path: str | None = None) -> None:
        raise WgplException("init failed")

    monkeypatch.setattr(wgpl_db_mod, "init_db", fail_init)

    with pytest.raises(WgplException, match="init failed"):
        core.restore_database(_VALID_RESTORE_SQL)

    assert not os.path.exists(f"{wgpl_db}.tmp")
