"""Database dump and restore with validation pipeline."""

from __future__ import annotations

import datetime
import fcntl
import glob
import os
import tempfile
from typing import cast

from . import db
from . import dbpath
from . import integrity
from .consistency import validate_state
from .exceptions import WgplException


def dump_database(target_path: str) -> None:
    """Creates a binary backup of the database to target_path."""
    with db.get_db() as conn:
        target_conn = dbpath.open_exclusive_sqlite(target_path)
        try:
            with target_conn:
                conn.backup(target_conn)
        finally:
            target_conn.close()


def _cleanup_tmp_files(tmp_path: str) -> None:
    """Remove the tmp database and any WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        path = f"{tmp_path}{suffix}"
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _rotate_backups(db_path: str, keep: int = 3) -> None:
    """Keep only the newest ``keep`` backup files matching ``{db_path}.bak.*``."""
    backups = sorted(
        glob.glob(f"{glob.escape(db_path)}.bak.*"),
        key=os.path.getmtime,
        reverse=True,
    )
    for old_backup in backups[keep:]:
        try:
            os.remove(old_backup)
        except OSError:
            pass


def _format_validation_issues(
    issues: list[dict[str, str | None]],
) -> str:
    return "; ".join(
        f"{issue.get('interface')}/{issue.get('peer')}: "
        f"{issue.get('code')} — {issue.get('detail')}"
        for issue in issues
    )


def _validate_restored_data() -> None:
    """Run consistency and full wire-format checks on WGPL_DB_PATH.

    Fail-closed on error-severity issues only. Warnings (e.g. a subnet router
    without an effective keepalive) never block a restore, matching the
    semantics of ``wgpl validate`` and ``integrity.assert_database_valid`` — a
    state the CLI can create must always be restorable from its own backup.
    """
    results = (
        validate_state(),
        integrity.validate_database(full=True),
    )
    errors: list[dict[str, str | None]] = []
    for result in results:
        for issue in cast(list[dict[str, str | None]], result["issues"]):
            if issue.get("severity", "error") == "error":
                errors.append(issue)
    if errors:
        raise WgplException(
            f"Restored database failed validation: {_format_validation_issues(errors)}"
        )


def _acquire_restore_lock(db_path: str) -> tuple[int, str]:
    """Acquire an exclusive non-blocking lock for database restore."""
    lock_path = f"{db_path}.restore.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(lock_fd)
        raise WgplException(
            "Database restore already in progress or the database is locked"
        ) from exc
    return lock_fd, lock_path


def _release_restore_lock(lock_fd: int, lock_path: str) -> None:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)
        try:
            os.unlink(lock_path)
        except OSError:
            pass


def _allocate_restore_tmp_path(db_path: str) -> str:
    """Return a unique temporary path for restore staging beside the live database."""
    parent = os.path.dirname(db_path) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=".wgpl-restore-",
        suffix=".tmp",
        dir=parent,
    )
    os.close(fd)
    os.unlink(tmp_path)
    return tmp_path


def restore_database(source_path: str) -> list[str]:
    """Safely restores the database from a binary SQLite backup."""
    warnings: list[str] = []
    db_path = db.get_db_path()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = f"{db_path}.bak.{timestamp}"

    lock_fd, lock_path = _acquire_restore_lock(db_path)
    tmp_path = _allocate_restore_tmp_path(db_path)
    _cleanup_tmp_files(tmp_path)

    try:
        dbpath.open_database(tmp_path, create=True, exclusive_create=True).close()

        try:
            tmp_conn = dbpath.open_existing_database(tmp_path)
            try:
                source_conn = dbpath.open_existing_database(source_path)
                try:
                    with source_conn:
                        source_conn.backup(tmp_conn)
                finally:
                    source_conn.close()
            finally:
                tmp_conn.close()
            db.assert_schema_contract(tmp_path)
        except WgplException:
            _cleanup_tmp_files(tmp_path)
            raise
        except Exception as e:
            _cleanup_tmp_files(tmp_path)
            raise WgplException(f"Failed to restore database from backup: {e}") from e

        saved_db_path = os.environ.get("WGPL_DB_PATH")
        try:
            os.environ["WGPL_DB_PATH"] = tmp_path
            try:
                db.init_db()
                _validate_restored_data()
            except BaseException:
                _cleanup_tmp_files(tmp_path)
                raise
        finally:
            if saved_db_path is None:
                os.environ.pop("WGPL_DB_PATH", None)
            else:
                os.environ["WGPL_DB_PATH"] = saved_db_path

        try:
            if os.path.exists(db_path):
                checkpoint_conn = dbpath.open_existing_database(db_path)
                try:
                    result = checkpoint_conn.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    ).fetchone()
                    if result and result[0] != 0:
                        warnings.append(
                            "Warning: WAL checkpoint was blocked. "
                            "Backup may not include uncommitted WAL data."
                        )
                finally:
                    checkpoint_conn.close()

                dbpath.copy_regular_file(db_path, backup_path)
                _rotate_backups(db_path, keep=3)
        except Exception:
            _cleanup_tmp_files(tmp_path)
            raise

        try:
            saved_revalidate = os.environ.get("WGPL_DB_PATH")
            os.environ["WGPL_DB_PATH"] = tmp_path
            try:
                pre_conn = dbpath.open_existing_database(tmp_path)
                try:
                    db.assert_trusted_connection(pre_conn)
                finally:
                    pre_conn.close()
                _validate_restored_data()
            finally:
                if saved_revalidate is None:
                    os.environ.pop("WGPL_DB_PATH", None)
                else:
                    os.environ["WGPL_DB_PATH"] = saved_revalidate

            os.replace(tmp_path, db_path)
            os.chmod(db_path, 0o600)
            for suffix in ("-wal", "-shm"):
                for path_base in (db_path, tmp_path):
                    sidecar = f"{path_base}{suffix}"
                    if os.path.exists(sidecar):
                        try:
                            os.remove(sidecar)
                        except OSError:
                            pass
        except Exception:
            _cleanup_tmp_files(tmp_path)
            raise
    finally:
        _release_restore_lock(lock_fd, lock_path)

    return warnings
