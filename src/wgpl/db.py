import sqlite3
import os
from contextlib import contextmanager
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

def get_db_path() -> str:
    """Returns the absolute path to the SQLite database file."""
    default_path = os.path.expanduser("~/.wgpl.db")
    return os.environ.get("WGPL_DB_PATH", default_path)

def _create_connection() -> sqlite3.Connection:
    """Creates a secure, atomic connection to the SQLite database."""
    db_path = get_db_path()
    
    try:
        fd = os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    except PermissionError:
        raise WgplException(f"Permission denied to access database at {db_path}. Try running with sudo or check file permissions.")
        
    # INVARIANT FIX: Always enforce 0o600, even if the file pre-existed.
    try:
        os.chmod(db_path, 0o600)
    except PermissionError:
        raise WgplException(f"Permission denied to secure database at {db_path}. Try running with sudo or check file ownership.")
            
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError as e:
        raise WgplException(f"Failed to connect to database at {db_path}: {e}")
    # PRAGMAs for safety and performance
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    
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
        conn.commit()

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
        cursor = c.execute("SELECT * FROM interfaces WHERE name = ?", (name,))
        return cursor.fetchone()

def list_interfaces(conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
    """Lists all configured interfaces."""
    with _ensure_conn(conn) as c:
        cursor = c.execute("SELECT * FROM interfaces ORDER BY name")
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
        cursor = c.execute("SELECT * FROM peers WHERE id = ?", (id,))
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
            cursor = c.execute(
                """
                SELECT * FROM peers
                WHERE REPLACE(LOWER(id), '-', '') LIKE ?
                  AND interface = ?
                ORDER BY interface, ip_address
                """,
                (like_pattern, interface),
            )
        else:
            cursor = c.execute(
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
            cursor = c.execute("SELECT * FROM peers WHERE interface = ? ORDER BY ip_address", (interface,))
        else:
            cursor = c.execute("SELECT * FROM peers ORDER BY interface, ip_address")
        return cursor.fetchall()

def remove_peer(id: str, conn: sqlite3.Connection | None = None) -> None:
    """Soft-removes a peer by its unique ID, retaining it in the database for auditing and IP management."""
    with _ensure_conn(conn, commit=True) as c:
        c.execute("UPDATE peers SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (id,))


def hard_remove_peer(id: str, conn: sqlite3.Connection | None = None) -> None:
    """Physically removes a peer from the database."""
    with _ensure_conn(conn, commit=True) as c:
        c.execute("DELETE FROM peers WHERE id = ?", (id,))


def prune_peers(interface: str, conn: sqlite3.Connection | None = None) -> int:
    """Physically removes all soft-deleted or expired peers for an interface. Returns the number of deleted rows."""
    with _ensure_conn(conn, commit=True) as c:
        cursor = c.execute(
            "DELETE FROM peers WHERE interface = ? AND (deleted_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP))",
            (interface,),
        )
        return cursor.rowcount


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
