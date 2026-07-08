import datetime
import json
import sqlite3
import os
from contextlib import contextmanager
from enum import StrEnum
from typing import Any, Generator

from .exceptions import (
    InterfaceAlreadyExistsError,
    InterfaceConflictError,
    InterfaceNotFoundError,
    PeerAlreadyExistsError,
    IpAlreadyInUseError,
    WgplException,
)
from . import dbpath


class _UnsetType:
    """Sentinel: field was not provided for a partial UPDATE."""


_UNSET = _UnsetType()
UNSET = _UNSET
UnsetType = _UnsetType

_FORBIDDEN_AUDIT_METADATA_KEYS = frozenset({"private_key", "preshared_key"})


class AuditEntityType(StrEnum):
    PEER = "peer"
    INTERFACE = "interface"


class AuditEventType(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REMOVED = "removed"
    RECLAIMED = "reclaimed"
    PRUNED = "pruned"
    CASCADE_REMOVED = "cascade_removed"


_MAX_AUDIT_METADATA_BYTES = 16_384
_MAX_AUDIT_METADATA_STRING_LEN = 2_048
_MAX_AUDIT_METADATA_DEPTH = 10


def get_db_path() -> str:
    """Returns the absolute path to the SQLite database file."""
    default_path = os.path.expanduser("~/.wgpl.db")
    path = os.environ.get("WGPL_DB_PATH", default_path)
    return dbpath.normalize_db_path(path)


def _normalize_db_path(db_path: str) -> str:
    return dbpath.normalize_db_path(db_path)


_SCHEMA_CONTRACT_MSG = (
    "Database failed schema contract. "
    "Restore from backup or run 'wgpl db doctor' for diagnosis."
)

_SCHEMA_CORRUPT_MSG = (
    "Database schema is invalid or corrupted. "
    "Run 'wgpl db restore' from a backup or 'wgpl db doctor'."
)

SCHEMA_USER_VERSION = 2

_REQUIRED_TABLES = frozenset({"interfaces", "peers", "audit_events"})
_REQUIRED_INDEXES = frozenset(
    {
        "idx_peers_active_ip",
        "idx_peers_active_name",
        "idx_audit_entity",
        "idx_audit_interface",
    }
)
_REQUIRED_AUDIT_TRIGGERS = frozenset(
    {
        "trg_audit_immutable_update",
        "trg_audit_immutable_delete",
    }
)
# SQLite internal objects from AUTOINCREMENT and UNIQUE constraints.
_ALLOWED_TABLES = _REQUIRED_TABLES | frozenset({"sqlite_sequence"})
_ALLOWED_VIEWS: frozenset[str] = frozenset()
_SUPPORTED_SCHEMA_VERSIONS = frozenset({0, SCHEMA_USER_VERSION})


def enforce_audit_immutability(conn: sqlite3.Connection) -> None:
    """Recreate audit immutability triggers (never IF NOT EXISTS)."""
    conn.execute("DROP TRIGGER IF EXISTS trg_audit_immutable_update")
    conn.execute("DROP TRIGGER IF EXISTS trg_audit_immutable_delete")
    conn.execute(_AUDIT_TRIGGER_UPDATE_BODY)
    conn.execute(_AUDIT_TRIGGER_DELETE_BODY)


_AUDIT_TRIGGER_UPDATE_BODY = """
        CREATE TRIGGER trg_audit_immutable_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events is an append-only log and cannot be updated');
        END;
        """

_AUDIT_TRIGGER_DELETE_BODY = """
        CREATE TRIGGER trg_audit_immutable_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events is an append-only log and cannot be deleted');
        END;
        """

_EXPECTED_TRIGGER_SQL = {
    "trg_audit_immutable_update": _AUDIT_TRIGGER_UPDATE_BODY,
    "trg_audit_immutable_delete": _AUDIT_TRIGGER_DELETE_BODY,
}


def _normalize_trigger_sql(sql: str) -> str:
    normalized = " ".join(sql.split())
    return normalized.rstrip(";")


def _is_database_initialized(conn: sqlite3.Connection) -> bool:
    return "interfaces" in _schema_objects(conn, "table")


def _assert_trigger_bodies(conn: sqlite3.Connection) -> None:
    for name, expected_body in _EXPECTED_TRIGGER_SQL.items():
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
            (name,),
        ).fetchone()
        if not row or not row[0]:
            raise WgplException(f"{_SCHEMA_CONTRACT_MSG} Missing trigger body: {name}")
        actual = _normalize_trigger_sql(str(row[0]))
        expected = _normalize_trigger_sql(expected_body.strip())
        if actual != expected:
            raise WgplException(
                f"{_SCHEMA_CONTRACT_MSG} Trigger {name} body does not match contract."
            )


def assert_trusted_connection(conn: sqlite3.Connection) -> None:
    """Validate schema contract and trigger bodies on an open connection."""
    if not _is_database_initialized(conn):
        return
    _assert_schema_contract_conn(conn)
    _assert_trigger_bodies(conn)


def assert_schema_contract(path: str) -> None:
    """Verify a database file satisfies the WGPL schema object contract."""
    conn = dbpath.open_existing_database(path)
    try:
        _assert_schema_contract_conn(conn)
    finally:
        conn.close()


def _schema_objects(conn: sqlite3.Connection, object_type: str) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = ? AND name IS NOT NULL",
            (object_type,),
        ).fetchall()
    }


def _assert_exact_schema_objects(
    conn: sqlite3.Connection,
    object_type: str,
    allowed: frozenset[str],
    *,
    label: str,
) -> None:
    present = _schema_objects(conn, object_type)
    missing = allowed - present
    if missing:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Missing required {label}: "
            f"{', '.join(sorted(missing))}"
        )
    extra = present - allowed
    if extra:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Unauthorized {label}: {', '.join(sorted(extra))}"
        )


def _assert_index_contract(conn: sqlite3.Connection) -> None:
    present = _schema_objects(conn, "index")
    missing = _REQUIRED_INDEXES - present
    if missing:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Missing required indexes: "
            f"{', '.join(sorted(missing))}"
        )
    extra = present - _REQUIRED_INDEXES
    unauthorized = {name for name in extra if not name.startswith("sqlite_autoindex_")}
    if unauthorized:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Unauthorized indexes: "
            f"{', '.join(sorted(unauthorized))}"
        )


def _assert_schema_contract_conn(conn: sqlite3.Connection) -> None:
    user_version = conn.execute("PRAGMA user_version").fetchone()
    version = int(user_version[0]) if user_version else 0
    if version == 1:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Unsupported schema version 1 (expected 2); "
            "backups with user_version 1 are not migratable."
        )
    if version not in _SUPPORTED_SCHEMA_VERSIONS:
        raise WgplException(
            f"{_SCHEMA_CONTRACT_MSG} Unsupported schema version {version} "
            f"(supported: {sorted(_SUPPORTED_SCHEMA_VERSIONS)})"
        )

    _assert_exact_schema_objects(conn, "table", _ALLOWED_TABLES, label="tables")
    _assert_index_contract(conn)
    _assert_exact_schema_objects(
        conn, "trigger", _REQUIRED_AUDIT_TRIGGERS, label="triggers"
    )
    _assert_exact_schema_objects(conn, "view", _ALLOWED_VIEWS, label="views")


def _run_query(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...] = (),
) -> sqlite3.Cursor:
    """Execute a read query, mapping sqlite errors to WgplException."""
    try:
        return conn.execute(sql, params)
    except sqlite3.DatabaseError as e:
        raise WgplException(f"{_SCHEMA_CORRUPT_MSG} ({e})") from e


def _create_connection(*, verify: bool = True) -> sqlite3.Connection:
    """Creates a secure, atomic connection to the SQLite database."""
    conn = dbpath.open_database(get_db_path(), create=True, exclusive_create=True)
    if verify:
        assert_trusted_connection(conn)
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Simple connection context manager for single-query operations."""
    conn = _create_connection()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _ensure_conn(
    conn: sqlite3.Connection | None, commit: bool = False
) -> Generator[sqlite3.Connection, None, None]:
    """Yields the provided connection, or creates a temporary one if None.

    When ``conn`` is provided, it is yielded as-is. The ``commit`` flag only
    applies to auto-created connections — the caller who owns the external
    connection is responsible for its transaction lifecycle.
    """
    if conn:
        yield conn
    else:
        with get_db() as c:
            yield c
            if commit:
                c.commit()


@contextmanager
def transaction(*, verify: bool = True) -> Generator[sqlite3.Connection, None, None]:
    """Provides an exclusive transaction context for multiple operations."""
    conn = _create_connection(verify=verify)
    try:
        # Prevent concurrent writes entirely
        conn.execute("BEGIN EXCLUSIVE TRANSACTION")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_current_actor() -> str:
    """Resolve the true identity of the caller for audit logs."""
    actor = os.environ.get("SUDO_USER")
    if not actor:
        actor = os.environ.get("USER")
    if not actor:
        try:
            actor = os.getlogin()
        except OSError:
            try:
                import pwd

                actor = pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                actor = "unknown"
    return actor


def init_db(path: str | None = None) -> None:
    """Initializes the database schema and enforces restrictive permissions."""
    if path:
        os.environ["WGPL_DB_PATH"] = _normalize_db_path(path)

    db_path = get_db_path()

    conn = dbpath.open_database(db_path, create=True, exclusive_create=False)
    try:
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS interfaces (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    name             TEXT NOT NULL,
                    endpoint         TEXT NOT NULL,
                    port             INTEGER NOT NULL DEFAULT 51820,
                    public_key       TEXT NOT NULL UNIQUE,
                    address_pool     TEXT NOT NULL,
                    dns              TEXT,
                    desc             TEXT,
                    mtu              INTEGER,
                    keepalive        INTEGER,
                    routed_networks  TEXT,
                    UNIQUE(name, endpoint, port)
                );
            """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS peers (
                    id                 TEXT PRIMARY KEY,
                    interface_id       INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
                    name               TEXT NOT NULL,
                    ip_address         TEXT NOT NULL,
                    public_key         TEXT NOT NULL,
                    private_key        TEXT NOT NULL,
                    preshared_key      TEXT,
                    created_at         TEXT NOT NULL,
                    dns                TEXT,
                    deleted_at         TEXT,
                    expires_at         TEXT,
                    desc               TEXT,
                    mtu                INTEGER,
                    keepalive          INTEGER,
                    role               TEXT NOT NULL DEFAULT 'endpoint'
                        CHECK(role IN ('endpoint', 'subnet_router')),
                    routed_networks    TEXT,
                    allowed_ips_policy TEXT NOT NULL DEFAULT 'vpn_only'
                        CHECK(allowed_ips_policy IN (
                            'vpn_only', 'split_tunnel', 'all_remote_networks',
                            'full_tunnel', 'custom')),
                    custom_allowed_ips TEXT,
                    CHECK(role = 'subnet_router' OR routed_networks IS NULL),
                    CHECK(allowed_ips_policy != 'custom' OR custom_allowed_ips IS NOT NULL)
                );
            """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_ip
                ON peers(interface_id, ip_address)
                WHERE deleted_at IS NULL;
            """
            )
            conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_name
                ON peers(interface_id, name)
                WHERE deleted_at IS NULL;
            """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type  TEXT NOT NULL CHECK(entity_type IN ('peer', 'interface')),
                    entity_id    TEXT NOT NULL,
                    interface    TEXT,
                    event_type   TEXT NOT NULL CHECK(event_type IN (
                        'created', 'updated', 'removed', 'reclaimed', 'pruned', 'cascade_removed'
                    )),
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
                """
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                ON audit_events(entity_type, entity_id);
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_interface
                ON audit_events(interface, occurred_at);
            """
            )
            enforce_audit_immutability(conn)
            conn.execute("UPDATE peers SET deleted_at = NULL WHERE deleted_at = ''")
            conn.execute(f"PRAGMA user_version = {SCHEMA_USER_VERSION}")
            conn.commit()
        except sqlite3.Error as e:
            raise WgplException(
                f"Failed to initialize database at {db_path}: {e}"
            ) from e
    finally:
        conn.close()

    if os.path.exists(db_path):
        os.chmod(db_path, 0o600)


# --- Interfaces CRUD ---


def add_interface(
    name: str,
    endpoint: str,
    public_key: str,
    address_pool: str,
    port: int = 51820,
    dns: str | None = None,
    desc: str | None = None,
    mtu: int | None = None,
    keepalive: int | None = None,
    routed_networks: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Adds a new WireGuard interface to the database and returns its ID."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            cursor = c.execute(
                "INSERT INTO interfaces (name, endpoint, port, public_key, address_pool, dns, desc, mtu, keepalive, routed_networks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    name,
                    endpoint,
                    port,
                    public_key,
                    address_pool,
                    dns,
                    desc,
                    mtu,
                    keepalive,
                    routed_networks,
                ),
            )
            if cursor.lastrowid is None:
                raise WgplException("Failed to persist interface: missing row id")
            return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "interfaces.public_key" in msg:
            raise InterfaceConflictError(
                f"Public key {public_key} is already used by another interface."
            )

        raise InterfaceAlreadyExistsError(
            f"Interface {name} with the same endpoint and port already exists."
        )


def get_interface(
    id: int, conn: sqlite3.Connection | None = None
) -> sqlite3.Row | None:
    """Retrieves an interface by its ID."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM interfaces WHERE id = ?", (id,))
        return cursor.fetchone()


def get_interfaces_by_name(
    name: str, conn: sqlite3.Connection | None = None
) -> list[sqlite3.Row]:
    """Retrieves all interfaces matching the given name."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(
            c, "SELECT * FROM interfaces WHERE name = ? ORDER BY id", (name,)
        )
        return cursor.fetchall()


def list_interfaces(conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
    """Lists all configured interfaces."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM interfaces ORDER BY name")
        return cursor.fetchall()


def remove_interface(id: int, conn: sqlite3.Connection | None = None) -> None:
    """Removes an interface and all its associated peers (CASCADE)."""
    with _ensure_conn(conn, commit=True) as c:
        cursor = c.execute("DELETE FROM interfaces WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise InterfaceNotFoundError(f"Interface ID {id} not found")


def update_interface(
    id: int,
    *,
    endpoint: str | _UnsetType = _UNSET,
    port: int | _UnsetType = _UNSET,
    public_key: str | _UnsetType = _UNSET,
    address_pool: str | _UnsetType = _UNSET,
    dns: str | None | _UnsetType = _UNSET,
    desc: str | None | _UnsetType = _UNSET,
    mtu: int | None | _UnsetType = _UNSET,
    keepalive: int | None | _UnsetType = _UNSET,
    routed_networks: str | None | _UnsetType = _UNSET,
    conn: sqlite3.Connection | None = None,
) -> None:
    """Update only the interface fields that are not _UNSET."""
    updates: list[str] = []
    params: list[Any] = []

    if endpoint is not _UNSET:
        updates.append("endpoint = ?")
        params.append(endpoint)
    if port is not _UNSET:
        updates.append("port = ?")
        params.append(port)
    if public_key is not _UNSET:
        updates.append("public_key = ?")
        params.append(public_key)
    if address_pool is not _UNSET:
        updates.append("address_pool = ?")
        params.append(address_pool)
    if dns is not _UNSET:
        updates.append("dns = ?")
        params.append(dns)
    if desc is not _UNSET:
        updates.append("desc = ?")
        params.append(desc)
    if mtu is not _UNSET:
        updates.append("mtu = ?")
        params.append(mtu)
    if keepalive is not _UNSET:
        updates.append("keepalive = ?")
        params.append(keepalive)
    if routed_networks is not _UNSET:
        updates.append("routed_networks = ?")
        params.append(routed_networks)

    if not updates:
        return

    params.append(id)
    try:
        with _ensure_conn(conn, commit=True) as c:
            # SQL field names come from internal fixed update clauses only.
            c.execute(
                f"UPDATE interfaces SET {', '.join(updates)} WHERE id = ?",
                params,
            )
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "interfaces.public_key" in msg:
            raise InterfaceConflictError(
                f"Public key {public_key} is already used by another interface."
            )
        raise InterfaceAlreadyExistsError(
            "Another interface with the same name, endpoint and port already exists."
        )


# --- Peers CRUD ---


def add_peer(
    id: str,
    interface_id: int,
    name: str,
    ip_address: str,
    public_key: str,
    private_key: str,
    created_at: str,
    preshared_key: str | None = None,
    dns: str | None = None,
    expires_at: str | None = None,
    desc: str | None = None,
    mtu: int | None = None,
    keepalive: int | None = None,
    role: str = "endpoint",
    routed_networks: str | None = None,
    allowed_ips_policy: str = "vpn_only",
    custom_allowed_ips: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> None:
    """Adds a new peer associated with a specific interface."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                """
                INSERT INTO peers (
                    id, interface_id, name, ip_address, public_key, private_key,
                    preshared_key, created_at, dns, expires_at, desc, mtu, keepalive,
                    role, routed_networks, allowed_ips_policy, custom_allowed_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    id,
                    interface_id,
                    name,
                    ip_address,
                    public_key,
                    private_key,
                    preshared_key,
                    created_at,
                    dns,
                    expires_at,
                    desc,
                    mtu,
                    keepalive,
                    role,
                    routed_networks,
                    allowed_ips_policy,
                    custom_allowed_ips,
                ),
            )
    except sqlite3.IntegrityError as exc:
        error_msg = str(exc).lower()
        if "ip_address" in error_msg:
            raise IpAlreadyInUseError(
                f"IP {ip_address} is already assigned in interface ID {interface_id}"
            ) from exc
        raise PeerAlreadyExistsError(
            f"Peer name '{name}' already exists in interface ID {interface_id}."
        ) from exc


def get_peer(id: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    """Retrieves a peer by its unique ID."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM peers WHERE id = ?", (id,))
        return cursor.fetchone()


def find_peers_by_id_prefix(
    prefix: str,
    interface_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[sqlite3.Row]:
    """Find peers whose hex ID (without hyphens) starts with prefix."""
    like_pattern = f"{prefix}%"
    with _ensure_conn(conn) as c:
        if interface_id is not None:
            cursor = _run_query(
                c,
                """
                SELECT * FROM peers
                WHERE REPLACE(LOWER(id), '-', '') LIKE ?
                  AND interface_id = ?
                ORDER BY interface_id, ip_address
                """,
                (like_pattern, interface_id),
            )
        else:
            cursor = _run_query(
                c,
                """
                SELECT * FROM peers
                WHERE REPLACE(LOWER(id), '-', '') LIKE ?
                ORDER BY interface_id, ip_address
                """,
                (like_pattern,),
            )
        return cursor.fetchall()


def find_deleted_peer_id_from_audit(
    prefix: str,
    interface_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[str]:
    """Find a peer's full UUID from the audit logs using its hex prefix."""
    like_pattern = f"{prefix}%"
    with _ensure_conn(conn) as c:
        if interface_id is not None:
            cursor = _run_query(
                c,
                """
                SELECT DISTINCT entity_id FROM audit_events
                WHERE entity_type = 'peer'
                  AND interface = ?
                  AND REPLACE(LOWER(entity_id), '-', '') LIKE ?
                """,
                (str(interface_id), like_pattern),
            )
        else:
            cursor = _run_query(
                c,
                """
                SELECT DISTINCT entity_id FROM audit_events
                WHERE entity_type = 'peer'
                  AND REPLACE(LOWER(entity_id), '-', '') LIKE ?
                """,
                (like_pattern,),
            )
        return [row["entity_id"] for row in cursor.fetchall()]


def diagnose_database(
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, str | None]]:
    """Return structural and consistency issues without mutating the database."""
    from .consistency import validate_state

    issues: list[dict[str, str | None]] = []
    with _ensure_conn(conn) as c:
        if not _is_database_initialized(c):
            return issues
        try:
            _assert_schema_contract_conn(c)
        except WgplException as exc:
            issues.append(
                {
                    "interface": None,
                    "peer": None,
                    "code": "schema_contract",
                    "detail": str(exc),
                }
            )
        try:
            _assert_trigger_bodies(c)
        except WgplException as exc:
            issues.append(
                {
                    "interface": None,
                    "peer": None,
                    "code": "trigger_bodies",
                    "detail": str(exc),
                }
            )
        for row in c.execute(
            "SELECT id, name FROM peers WHERE deleted_at = ''"
        ).fetchall():
            issues.append(
                {
                    "interface": None,
                    "peer": str(row["name"]),
                    "code": "empty_deleted_at",
                    "detail": f"Peer {row['name']} has deleted_at='' (should be NULL)",
                }
            )
    result = validate_state()
    if result["status"] != "ok":
        issues.extend(result["issues"])  # type: ignore[arg-type]
    return issues


def repair_database(
    conn: sqlite3.Connection | None = None,
) -> list[str]:
    """Apply documented repairs: normalize deleted_at and reinstall audit triggers."""
    actions: list[str] = []

    def _repair(c: sqlite3.Connection) -> None:
        cursor = c.execute("UPDATE peers SET deleted_at = NULL WHERE deleted_at = ''")
        if cursor.rowcount:
            actions.append(f"Normalized deleted_at for {cursor.rowcount} peer row(s)")
        enforce_audit_immutability(c)

    if conn is not None:
        _repair(conn)
        conn.commit()
    else:
        with transaction(verify=False) as c:
            _repair(c)
    if not actions:
        actions.append("Reinstalled audit immutability triggers")
    return actions


def list_peers(
    interface_id: int | None = None, conn: sqlite3.Connection | None = None
) -> list[sqlite3.Row]:
    """Lists all peers, optionally filtered by a specific interface ID."""
    with _ensure_conn(conn) as c:
        if interface_id is not None:
            cursor = _run_query(
                c,
                "SELECT * FROM peers WHERE interface_id = ? ORDER BY ip_address",
                (interface_id,),
            )
        else:
            cursor = _run_query(
                c, "SELECT * FROM peers ORDER BY interface_id, ip_address"
            )
        return cursor.fetchall()


def remove_peer(id: str, conn: sqlite3.Connection | None = None) -> None:
    """Soft-removes a peer by its unique ID, retaining it in the database for auditing and IP management."""
    deleted_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _ensure_conn(conn, commit=True) as c:
        c.execute("UPDATE peers SET deleted_at = ? WHERE id = ?", (deleted_at, id))


def hard_remove_peer(id: str, conn: sqlite3.Connection | None = None) -> None:
    """Physically removes a peer from the database."""
    with _ensure_conn(conn, commit=True) as c:
        c.execute("DELETE FROM peers WHERE id = ?", (id,))


def update_peer(
    peer_id: str,
    *,
    name: str | _UnsetType = _UNSET,
    ip_address: str | _UnsetType = _UNSET,
    dns: str | None | _UnsetType = _UNSET,
    desc: str | None | _UnsetType = _UNSET,
    mtu: int | None | _UnsetType = _UNSET,
    keepalive: int | None | _UnsetType = _UNSET,
    expires_at: str | None | _UnsetType = _UNSET,
    role: str | _UnsetType = _UNSET,
    routed_networks: str | None | _UnsetType = _UNSET,
    allowed_ips_policy: str | _UnsetType = _UNSET,
    custom_allowed_ips: str | None | _UnsetType = _UNSET,
    conn: sqlite3.Connection | None = None,
) -> None:
    """Update only the peer fields that are not _UNSET."""
    updates: list[str] = []
    params: list[Any] = []

    if name is not _UNSET:
        updates.append("name = ?")
        params.append(name)
    if ip_address is not _UNSET:
        updates.append("ip_address = ?")
        params.append(ip_address)
    if dns is not _UNSET:
        updates.append("dns = ?")
        params.append(dns)
    if desc is not _UNSET:
        updates.append("desc = ?")
        params.append(desc)
    if mtu is not _UNSET:
        updates.append("mtu = ?")
        params.append(mtu)
    if keepalive is not _UNSET:
        updates.append("keepalive = ?")
        params.append(keepalive)
    if expires_at is not _UNSET:
        updates.append("expires_at = ?")
        params.append(expires_at)
    if role is not _UNSET:
        updates.append("role = ?")
        params.append(role)
    if routed_networks is not _UNSET:
        updates.append("routed_networks = ?")
        params.append(routed_networks)
    if allowed_ips_policy is not _UNSET:
        updates.append("allowed_ips_policy = ?")
        params.append(allowed_ips_policy)
    if custom_allowed_ips is not _UNSET:
        updates.append("custom_allowed_ips = ?")
        params.append(custom_allowed_ips)

    if not updates:
        return

    params.append(peer_id)
    try:
        with _ensure_conn(conn, commit=True) as c:
            # SQL field names come from internal fixed update clauses only.
            c.execute(
                f"UPDATE peers SET {', '.join(updates)} WHERE id = ?",
                params,
            )
    except sqlite3.IntegrityError as exc:
        err_msg = str(exc).lower()
        if "name" in err_msg and name is not _UNSET:
            raise PeerAlreadyExistsError(
                f"Peer name '{name}' already exists in this interface."
            ) from exc
        if "ip_address" in err_msg and ip_address is not _UNSET:
            raise IpAlreadyInUseError(
                f"IP {ip_address} is already assigned in this interface"
            ) from exc
        raise


# --- Audit log (append-only) ---


def _validate_audit_metadata(metadata: dict[str, Any] | None) -> None:
    if not metadata:
        return

    def _validate_value(value: Any, depth: int) -> None:
        if depth > _MAX_AUDIT_METADATA_DEPTH:
            raise WgplException("Audit metadata is too deeply nested")

        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    raise WgplException("Audit metadata keys must be strings")
                if k.lower() in _FORBIDDEN_AUDIT_METADATA_KEYS:
                    raise WgplException(
                        f"Audit metadata must not contain secret field '{k}'"
                    )
                _validate_value(v, depth + 1)
            return

        if isinstance(value, list):
            for item in value:
                _validate_value(item, depth + 1)
            return

        if isinstance(value, str):
            if len(value) > _MAX_AUDIT_METADATA_STRING_LEN:
                raise WgplException("Audit metadata string value is too large")
            # Keep metadata JSON-safe and avoid control character injection.
            if any(ord(ch) < 0x20 and ch not in {"\n", "\r", "\t"} for ch in value):
                raise WgplException("Audit metadata contains unsafe control characters")
            return

        if value is None:
            return
        if isinstance(value, (int, float, bool)):
            return

        raise WgplException("Audit metadata must be JSON-serializable")

    _validate_value(metadata, 0)

    # Ensure total serialized metadata stays bounded.
    try:
        metadata_json = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    except TypeError as exc:
        raise WgplException("Audit metadata must be JSON-serializable") from exc

    if len(metadata_json.encode("utf-8")) > _MAX_AUDIT_METADATA_BYTES:
        raise WgplException("Audit metadata exceeds maximum allowed size")


def append_audit_event(
    *,
    entity_type: AuditEntityType,
    entity_id: str,
    event_type: AuditEventType,
    interface: str | None = None,
    name: str | None = None,
    ip_address: str | None = None,
    public_key: str | None = None,
    metadata: dict[str, Any] | None = None,
    occurred_at: str | None = None,
    actor: str | None = None,
    conn: sqlite3.Connection,
) -> None:
    """Insert an append-only audit row. Caller must own the transaction."""
    _validate_audit_metadata(metadata)
    if occurred_at is None:
        occurred_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if actor is None:
        actor = get_current_actor()

    metadata_json = json.dumps(metadata) if metadata is not None else None
    conn.execute(
        """
        INSERT INTO audit_events (
            entity_type, entity_id, interface, event_type, occurred_at,
            actor, name, ip_address, public_key, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entity_type.value,
            entity_id,
            interface,
            event_type.value,
            occurred_at,
            actor,
            name,
            ip_address,
            public_key,
            metadata_json,
        ),
    )


def list_audit_events(
    *,
    entity_type: AuditEntityType | None = None,
    entity_id: str | None = None,
    interface: str | None = None,
    limit: int = 100,
    offset: int = 0,
    conn: sqlite3.Connection | None = None,
) -> list[sqlite3.Row]:
    """Return the most recent audit events first (occurred_at descending)."""
    clauses: list[str] = []
    params: list[Any] = []
    if entity_type is not None:
        clauses.append("entity_type = ?")
        params.append(entity_type.value)
    if entity_id is not None:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    if interface is not None:
        clauses.append("interface = ?")
        params.append(interface)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])
    # WHERE is assembled from constant fragments with bound params for values.
    sql = (
        f"SELECT * FROM audit_events {where} "
        "ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with _ensure_conn(conn) as c:
        return _run_query(c, sql, tuple(params)).fetchall()
