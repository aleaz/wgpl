import sqlite3
import os
from contextlib import contextmanager
from typing import Generator

from .exceptions import InterfaceAlreadyExistsError, PeerAlreadyExistsError, WgplException

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
    """Yields the provided connection, or creates a temporary one if None."""
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
                port         INTEGER NOT NULL DEFAULT 51820,
                public_key   TEXT NOT NULL,
                address_pool TEXT NOT NULL,
                dns          TEXT
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
                UNIQUE(interface, ip_address),
                UNIQUE(interface, name)
            );
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
    conn: sqlite3.Connection | None = None,
) -> None:
    """Adds a new WireGuard interface to the database."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                "INSERT INTO interfaces (name, endpoint, port, public_key, address_pool, dns) VALUES (?, ?, ?, ?, ?, ?)",
                (name, endpoint, port, public_key, address_pool, dns),
            )
    except sqlite3.IntegrityError:
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
        c.execute("DELETE FROM interfaces WHERE name = ?", (name,))

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
    conn: sqlite3.Connection | None = None,
) -> None:
    """Adds a new peer associated with a specific interface."""
    try:
        with _ensure_conn(conn, commit=True) as c:
            c.execute(
                "INSERT INTO peers (id, interface, name, ip_address, public_key, private_key, preshared_key, created_at, dns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (id, interface, name, ip_address, public_key, private_key, preshared_key, created_at, dns),
            )
    except sqlite3.IntegrityError:
        raise PeerAlreadyExistsError(f"Peer name '{name}' already exists in interface '{interface}'.")

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
    """Removes a peer by its unique ID."""
    with _ensure_conn(conn, commit=True) as c:
        c.execute("DELETE FROM peers WHERE id = ?", (id,))
