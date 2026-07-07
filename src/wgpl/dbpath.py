"""Secure SQLite database path handling."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys

from .exceptions import WgplException

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def normalize_db_path(db_path: str) -> str:
    """Normalize DB path and reject invalid targets."""
    if not isinstance(db_path, str) or not db_path.strip():
        raise WgplException("Database path must be a non-empty string")
    if "\x00" in db_path:
        raise WgplException("Database path contains invalid null bytes")
    expanded = os.path.expanduser(db_path)
    return os.path.abspath(expanded)


def validate_path_target(db_path: str) -> None:
    """Reject symlinks, directories, and non-regular files at db_path."""
    try:
        st = os.lstat(db_path)
    except FileNotFoundError:
        return

    if stat.S_ISLNK(st.st_mode):
        raise WgplException(f"Database path must not be a symlink: {db_path}")

    if stat.S_ISDIR(st.st_mode):
        raise WgplException(f"Database path is a directory: {db_path}")

    if not stat.S_ISREG(st.st_mode):
        raise WgplException(
            f"Database path must be a regular file (got mode {st.st_mode:o}): {db_path}"
        )


def _connect_via_fd(fd: int) -> sqlite3.Connection:
    if sys.platform.startswith("linux"):
        return sqlite3.connect(f"/proc/self/fd/{fd}")
    return sqlite3.connect(f"/dev/fd/{fd}")


def secure_open(
    db_path: str,
    *,
    create: bool = False,
    exclusive_create: bool = False,
) -> int:
    """Open a database file with O_NOFOLLOW when available."""
    path = normalize_db_path(db_path)
    validate_path_target(path)

    flags = os.O_RDWR
    if create:
        flags |= os.O_CREAT
    if exclusive_create:
        flags |= os.O_EXCL
    if _O_NOFOLLOW:
        flags |= _O_NOFOLLOW

    try:
        return os.open(path, flags, 0o600)
    except FileExistsError:
        raise
    except FileNotFoundError:
        parent = os.path.dirname(path) or "."
        raise WgplException(f"Database directory does not exist: {parent}") from None
    except IsADirectoryError:
        raise WgplException(f"Database path is a directory: {path}") from None
    except PermissionError:
        raise WgplException(
            f"Permission denied to access database at {path}. "
            "Try running with sudo or check file permissions."
        ) from None


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row


def _attach_fd_cleanup(conn: sqlite3.Connection, fd: int) -> None:
    """Keep the backing fd open until conn.close() (required on macOS /dev/fd)."""
    _original_close = conn.close

    def close() -> None:
        try:
            _original_close()
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    conn.close = close  # type: ignore[method-assign]


def open_database(
    db_path: str,
    *,
    create: bool = True,
    exclusive_create: bool = False,
) -> sqlite3.Connection:
    """Open a SQLite database through a validated file descriptor."""
    path = normalize_db_path(db_path)
    validate_path_target(path)

    fd: int | None = None
    try:
        if create and not os.path.exists(path):
            fd = secure_open(path, create=True, exclusive_create=True)
        else:
            fd = secure_open(path, create=False)
    except FileExistsError:
        fd = secure_open(path, create=False)

    if fd is None:
        raise WgplException(f"Failed to open database at {path}")
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        os.close(fd)
        raise WgplException(
            f"Permission denied to secure database at {path}. "
            "Try running with sudo or check file ownership."
        ) from None

    if sys.platform.startswith("linux"):
        try:
            conn = _connect_via_fd(fd)
        except sqlite3.Error as exc:
            os.close(fd)
            raise WgplException(
                f"Failed to connect to database at {path}: {exc}"
            ) from exc
        try:
            _configure_connection(conn)
        except sqlite3.Error as exc:
            os.close(fd)
            raise WgplException(
                f"Failed to connect to database at {path}: {exc}"
            ) from exc
        _attach_fd_cleanup(conn, fd)
        return conn

    # macOS/BSD: WAL needs a path-based open; fd was used only to validate O_NOFOLLOW target.
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        _configure_connection(conn)
    except sqlite3.Error as exc:
        raise WgplException(f"Failed to connect to database at {path}: {exc}") from exc
    return conn


def open_existing_database(db_path: str) -> sqlite3.Connection:
    """Open an existing database file without creating it."""
    return open_database(db_path, create=False)
