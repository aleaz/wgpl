"""Secure SQLite database path handling."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys

from .exceptions import WgplException

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def normalize_db_path(db_path: str, *, label: str = "Database path") -> str:
    """Normalize DB path and reject invalid targets."""
    if not isinstance(db_path, str) or not db_path.strip():
        raise WgplException(f"{label} must be a non-empty string")
    if "\x00" in db_path:
        raise WgplException(f"{label} contains invalid null bytes")
    expanded = os.path.expanduser(db_path)
    return os.path.abspath(expanded)


def validate_path_target(db_path: str, *, label: str = "Database path") -> None:
    """Reject symlinks, directories, and non-regular files at db_path."""
    try:
        st = os.lstat(db_path)
    except FileNotFoundError:
        return

    if stat.S_ISLNK(st.st_mode):
        raise WgplException(f"{label} must not be a symlink: {db_path}")

    if stat.S_ISDIR(st.st_mode):
        raise WgplException(f"{label} is a directory: {db_path}")

    if not stat.S_ISREG(st.st_mode):
        raise WgplException(
            f"{label} must be a regular file (got mode {st.st_mode:o}): {db_path}"
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
            "Check file ownership and mode (expect 600), or pass --db / set "
            "WGPL_DB_PATH to a path you can read and write."
        ) from None


def _validate_parent_directory(parent: str, *, label: str = "Output path") -> None:
    """Reject symlink parent directories for output and dump targets."""
    try:
        st = os.lstat(parent)
    except FileNotFoundError:
        raise WgplException(f"Output directory does not exist: {parent}") from None
    if stat.S_ISLNK(st.st_mode):
        raise WgplException(f"{label} parent directory must not be a symlink: {parent}")
    if not stat.S_ISDIR(st.st_mode):
        raise WgplException(f"{label} parent is not a directory: {parent}")


def open_exclusive_output(output_path: str) -> int:
    """Create an exclusive output file (O_NOFOLLOW, O_EXCL, mode 0o600)."""
    path = normalize_db_path(output_path, label="Output path")
    validate_path_target(path, label="Output path")
    parent = os.path.dirname(path) or "."
    _validate_parent_directory(parent, label="Output path")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if _O_NOFOLLOW:
        flags |= _O_NOFOLLOW

    try:
        return os.open(path, flags, 0o600)
    except FileExistsError:
        raise WgplException(f"Output file already exists: {path}") from None
    except IsADirectoryError:
        raise WgplException(f"Output path is a directory: {path}") from None
    except OSError as exc:
        if exc.errno == getattr(os, "ELOOP", 0):
            raise WgplException(f"Output path must not be a symlink: {path}") from exc
        raise WgplException(f"Failed to create output file at {path}: {exc}") from exc


def open_exclusive_sqlite(path: str) -> sqlite3.Connection:
    """Create an exclusive SQLite database file (O_NOFOLLOW, O_EXCL, mode 0o600)."""
    normalized = normalize_db_path(path, label="Output path")
    parent = os.path.dirname(normalized) or "."
    _validate_parent_directory(parent, label="Output path")
    validate_path_target(normalized, label="Output path")

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if _O_NOFOLLOW:
        flags |= _O_NOFOLLOW
    try:
        fd = os.open(normalized, flags, 0o600)
    except FileExistsError:
        raise WgplException(f"Output file already exists: {normalized}") from None
    except OSError as exc:
        if exc.errno == getattr(os, "ELOOP", 0):
            raise WgplException(
                f"Output path must not be a symlink: {normalized}"
            ) from exc
        raise WgplException(
            f"Failed to create output database at {normalized}: {exc}"
        ) from exc

    _fchmod_path(fd, normalized)
    fd_closed = False
    try:
        if sys.platform.startswith("linux"):
            conn = _connect_via_fd(fd)
            os.close(fd)
            fd_closed = True
        else:
            fd_stat = os.fstat(fd)
            os.close(fd)
            fd_closed = True
            path_stat = os.stat(normalized)
            if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
                raise WgplException(
                    f"Output path changed between validation and open: {normalized}"
                )
            conn = sqlite3.connect(normalized)
        _configure_connection(conn)
        return conn
    except BaseException:
        if not fd_closed:
            os.close(fd)
        try:
            os.unlink(normalized)
        except OSError:
            pass
        raise


def copy_regular_file(
    src_path: str, dst_path: str, *, label: str = "Database path"
) -> None:
    """Copy a validated regular file from src to dst without following symlinks."""
    src = normalize_db_path(src_path, label=label)
    dst = normalize_db_path(dst_path, label=label)
    validate_path_target(src, label=label)
    parent = os.path.dirname(dst) or "."
    _validate_parent_directory(parent, label=label)
    validate_path_target(dst, label=label)

    src_fd = secure_open(src, create=False)
    dst_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if _O_NOFOLLOW:
        dst_flags |= _O_NOFOLLOW
    try:
        dst_fd = os.open(dst, dst_flags, 0o600)
    except FileExistsError:
        os.close(src_fd)
        raise WgplException(f"Backup file already exists: {dst}") from None
    try:
        while True:
            chunk = os.read(src_fd, 1024 * 1024)
            if not chunk:
                break
            os.write(dst_fd, chunk)
    finally:
        os.close(src_fd)
        os.close(dst_fd)
    os.chmod(dst, 0o600)


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row


def _fchmod_path(fd: int, path: str) -> None:
    try:
        os.fchmod(fd, 0o600)
    except PermissionError:
        raise WgplException(
            f"Permission denied to secure database at {path}. "
            "Check file ownership and mode, or use --db / WGPL_DB_PATH."
        ) from None


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

    _fchmod_path(fd, path)

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
        os.close(fd)
        return conn

    # macOS/BSD: WAL needs a path-based open; fd validates O_NOFOLLOW target.
    fd_stat = os.fstat(fd)
    os.close(fd)
    try:
        path_stat = os.stat(path)
    except OSError as exc:
        raise WgplException(f"Failed to stat database at {path}: {exc}") from exc
    if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
        raise WgplException(
            f"Database path changed between validation and open: {path}"
        )
    try:
        conn = sqlite3.connect(path)
        _configure_connection(conn)
    except sqlite3.Error as exc:
        raise WgplException(f"Failed to connect to database at {path}: {exc}") from exc
    return conn


def open_existing_database(db_path: str) -> sqlite3.Connection:
    """Open an existing database file without creating it."""
    return open_database(db_path, create=False)
