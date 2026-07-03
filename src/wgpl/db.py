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

def get_db_path() -> str:
    """Returns the absolute path to the SQLite database file."""
    default_path = os.path.expanduser("~/.wgpl.db")
    return os.environ.get("WGPL_DB_PATH", default_path)

_SCHEMA_CORRUPT_MSG = (
    "Database schema is invalid or corrupted. "
    "Run 'wgpl db restore' from a backup or remove the file and re-init."
)

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

def _create_connection() -> sqlite3.Connection:
    """Creates a secure, atomic connection to the SQLite database."""
    db_path = get_db_path()

    if os.path.isdir(db_path):
        raise WgplException(f"Database path is a directory: {db_path}")

    try:
        fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    except FileNotFoundError:
        parent = os.path.dirname(db_path) or "."
        raise WgplException(f"Database directory does not exist: {parent}") from None
    except IsADirectoryError:
        raise WgplException(f"Database path is a directory: {db_path}") from None
    except PermissionError:
        raise WgplException(
            f"Permission denied to access database at {db_path}. "
            "Try running with sudo or check file permissions."
        ) from None
        
    # INVARIANT FIX: Always enforce 0o600, even if the file pre-existed.
    try:
        os.chmod(db_path, 0o600)
    except PermissionError:
        raise WgplException(f"Permission denied to secure database at {db_path}. Try running with sudo or check file ownership.")
            
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error as e:
        raise WgplException(f"Failed to connect to database at {db_path}: {e}") from e
    # PRAGMAs for safety and performance
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
    except sqlite3.Error as e:
        conn.close()
        raise WgplException(f"Failed to connect to database at {db_path}: {e}") from e
    
    # We want dictionary-like rows
    conn.row_factory = sqlite3.Row
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
def _ensure_conn(conn: sqlite3.Connection | None, commit: bool = False) -> Generator[sqlite3.Connection, None, None]:
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
def transaction() -> Generator[sqlite3.Connection, None, None]:
    """Provides an exclusive transaction context for multiple operations."""
    conn = _create_connection()
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

def init_db(path: str | None = None) -> None:
    """Initializes the database schema and enforces restrictive permissions."""
    if path:
        os.environ["WGPL_DB_PATH"] = path
    
    db_path = get_db_path()
    
    with get_db() as conn:
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS interfaces (
                    name         TEXT PRIMARY KEY,
                    endpoint     TEXT NOT NULL,
                    port         INTEGER NOT NULL DEFAULT 51820 UNIQUE,
                    public_key   TEXT NOT NULL,
                    address_pool TEXT NOT NULL UNIQUE,
                    dns          TEXT,
                    desc         TEXT,
                    mtu          INTEGER,
                    keepalive    INTEGER
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    id           TEXT PRIMARY KEY,
                    interface    TEXT NOT NULL REFERENCES interfaces(name) ON DELETE CASCADE,
                    name         TEXT NOT NULL,
                    ip_address   TEXT NOT NULL,
                    public_key   TEXT NOT NULL,
                    private_key  TEXT NOT NULL,
                    preshared_key TEXT,
                    created_at   TEXT NOT NULL,
                    dns          TEXT,
                    deleted_at   TEXT,
                    expires_at   TEXT,
                    desc         TEXT,
                    mtu          INTEGER,
                    keepalive    INTEGER
                );
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_ip
                ON peers(interface, ip_address)
                WHERE deleted_at IS NULL;
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_active_name
                ON peers(interface, name)
                WHERE deleted_at IS NULL;
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type  TEXT NOT NULL CHECK(entity_type IN ('peer', 'interface')),
                    entity_id    TEXT NOT NULL,
                    interface    TEXT,
                    event_type   TEXT NOT NULL CHECK(event_type IN (
                        'created', 'updated', 'removed', 'reclaimed', 'pruned', 'cascade_removed'
                    )),
                    occurred_at  TEXT NOT NULL,
                    name         TEXT,
                    ip_address   TEXT,
                    public_key   TEXT,
                    metadata     TEXT
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                ON audit_events(entity_type, entity_id);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_interface
                ON audit_events(interface, occurred_at);
            """)
            conn.commit()
        except sqlite3.Error as e:
            raise WgplException(f"Failed to initialize database at {db_path}: {e}") from e

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
    conn: sqlite3.Connection | None = None,
) -> None:
    """Adds a new WireGuard interface to the database."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                "INSERT INTO interfaces (name, endpoint, port, public_key, address_pool, dns, desc, mtu, keepalive) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, endpoint, port, public_key, address_pool, dns, desc, mtu, keepalive),
            )
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "interfaces.port" in msg:
            raise InterfaceConflictError(f"Port {port} is already used by another interface.")
        if "interfaces.address_pool" in msg:
            raise InterfaceConflictError(f"Address pool {address_pool} is already used by another interface.")
        
        raise InterfaceAlreadyExistsError(f"Interface {name} already exists.")

def get_interface(name: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    """Retrieves an interface by its name."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM interfaces WHERE name = ?", (name,))
        return cursor.fetchone()

def list_interfaces(conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
    """Lists all configured interfaces."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM interfaces ORDER BY name")
        return cursor.fetchall()

def remove_interface(name: str, conn: sqlite3.Connection | None = None) -> None:
    """Removes an interface and all its associated peers (CASCADE)."""
    with _ensure_conn(conn, commit=True) as c:
        cursor = c.execute("DELETE FROM interfaces WHERE name = ?", (name,))
        if cursor.rowcount == 0:
            raise InterfaceNotFoundError(f"Interface {name} not found")


def update_interface(
    name: str,
    *,
    endpoint: str | _UnsetType = _UNSET,
    port: int | _UnsetType = _UNSET,
    public_key: str | _UnsetType = _UNSET,
    address_pool: str | _UnsetType = _UNSET,
    dns: str | None | _UnsetType = _UNSET,
    desc: str | None | _UnsetType = _UNSET,
    mtu: int | None | _UnsetType = _UNSET,
    keepalive: int | None | _UnsetType = _UNSET,
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

    if not updates:
        return

    params.append(name)
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                f"UPDATE interfaces SET {', '.join(updates)} WHERE name = ?",
                params,
            )
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "interfaces.port" in msg:
            raise InterfaceConflictError(f"Port {port} is already used by another interface.")
        if "interfaces.address_pool" in msg:
            raise InterfaceConflictError(f"Address pool {address_pool} is already used by another interface.")
        raise

# --- Peers CRUD ---

def add_peer(
    id: str,
    interface: str,
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
    conn: sqlite3.Connection | None = None,
) -> None:
    """Adds a new peer associated with a specific interface."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                "INSERT INTO peers (id, interface, name, ip_address, public_key, private_key, preshared_key, created_at, dns, expires_at, desc, mtu, keepalive) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id, interface, name, ip_address, public_key, private_key, preshared_key, created_at, dns, expires_at, desc, mtu, keepalive),
            )
    except sqlite3.IntegrityError as exc:
        error_msg = str(exc).lower()
        if "ip_address" in error_msg:
            raise IpAlreadyInUseError(
                f"IP {ip_address} is already assigned in interface '{interface}'"
            ) from exc
        raise PeerAlreadyExistsError(
            f"Peer name '{name}' already exists in interface '{interface}'."
        ) from exc

def get_peer(id: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    """Retrieves a peer by its unique ID."""
    with _ensure_conn(conn) as c:
        cursor = _run_query(c, "SELECT * FROM peers WHERE id = ?", (id,))
        return cursor.fetchone()

def find_peers_by_id_prefix(
    prefix: str,
    interface: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[sqlite3.Row]:
    """Find peers whose hex ID (without hyphens) starts with prefix."""
    like_pattern = f"{prefix}%"
    with _ensure_conn(conn) as c:
        if interface:
            cursor = _run_query(
                c,
                """
                SELECT * FROM peers
                WHERE REPLACE(LOWER(id), '-', '') LIKE ?
                  AND interface = ?
                ORDER BY interface, ip_address
                """,
                (like_pattern, interface),
            )
        else:
            cursor = _run_query(
                c,
                """
                SELECT * FROM peers
                WHERE REPLACE(LOWER(id), '-', '') LIKE ?
                ORDER BY interface, ip_address
                """,
                (like_pattern,),
            )
        return cursor.fetchall()

def list_peers(interface: str | None = None, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
    """Lists all peers, optionally filtered by a specific interface."""
    with _ensure_conn(conn) as c:
        if interface:
            cursor = _run_query(
                c,
                "SELECT * FROM peers WHERE interface = ? ORDER BY ip_address",
                (interface,),
            )
        else:
            cursor = _run_query(c, "SELECT * FROM peers ORDER BY interface, ip_address")
        return cursor.fetchall()

def remove_peer(id: str, conn: sqlite3.Connection | None = None) -> None:
    """Soft-removes a peer by its unique ID, retaining it in the database for auditing and IP management."""
    with _ensure_conn(conn, commit=True) as c:
        c.execute("UPDATE peers SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (id,))


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

    if not updates:
        return

    params.append(peer_id)
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                f"UPDATE peers SET {', '.join(updates)} WHERE id = ?",
                params,
            )
    except sqlite3.IntegrityError as exc:
        if name is not _UNSET:
            raise PeerAlreadyExistsError(
                f"Peer name '{name}' already exists in this interface."
            ) from exc
        if ip_address is not _UNSET:
            raise IpAlreadyInUseError(
                f"IP {ip_address} is already assigned in this interface"
            ) from exc
        raise


# --- Audit log (append-only) ---


def _validate_audit_metadata(metadata: dict[str, Any] | None) -> None:
    if not metadata:
        return
    for key in metadata:
        if key.lower() in _FORBIDDEN_AUDIT_METADATA_KEYS:
            raise WgplException(f"Audit metadata must not contain secret field '{key}'")


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
    conn: sqlite3.Connection,
) -> None:
    """Insert an append-only audit row. Caller must own the transaction."""
    _validate_audit_metadata(metadata)
    if occurred_at is None:
        from datetime import datetime, timezone

        occurred_at = datetime.now(timezone.utc).isoformat()
    metadata_json = json.dumps(metadata) if metadata is not None else None
    conn.execute(
        """
        INSERT INTO audit_events (
            entity_type, entity_id, interface, event_type, occurred_at,
            name, ip_address, public_key, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entity_type.value,
            entity_id,
            interface,
            event_type.value,
            occurred_at,
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
    params.append(limit)
    sql = f"SELECT * FROM audit_events {where} ORDER BY occurred_at DESC, id DESC LIMIT ?"
    with _ensure_conn(conn) as c:
        return _run_query(c, sql, tuple(params)).fetchall()
