"""Database dump and restore with validation pipeline."""

from __future__ import annotations

import datetime
import glob
import os
import shutil
from typing import cast

from . import db
from . import dbpath
from . import integrity
from .consistency import validate_state
from .exceptions import WgplException


def dump_database(target_path: str) -> None:
    """Creates a binary backup of the database to target_path."""
    with db.get_db() as conn:
        target_conn = dbpath.open_database(
            target_path, create=True, exclusive_create=True
        )
        try:
            with target_conn:
                conn.backup(target_conn)
        finally:
            target_conn.close()
    os.chmod(target_path, 0o600)


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
        glob.glob(f"{db_path}.bak.*"),
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
    """Run consistency and full wire-format checks on WGPL_DB_PATH."""
    results = (
        validate_state(),
        integrity.validate_database(full=True),
    )
    issues: list[dict[str, str | None]] = []
    for result in results:
        if result["status"] != "ok":
            issues.extend(cast(list[dict[str, str | None]], result["issues"]))
    if issues:
        raise WgplException(
            f"Restored database failed validation: {_format_validation_issues(issues)}"
        )


def restore_database(source_path: str) -> list[str]:
    """Safely restores the database from a binary SQLite backup."""
    warnings: list[str] = []
    db_path = db.get_db_path()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = f"{db_path}.bak.{timestamp}"
    tmp_path = f"{db_path}.tmp"

    _cleanup_tmp_files(tmp_path)

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
            _validate_restored_data()
            db.init_db()
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

            shutil.copy2(db_path, backup_path)
            os.chmod(backup_path, 0o600)
            _rotate_backups(db_path, keep=3)
    except Exception:
        _cleanup_tmp_files(tmp_path)
        raise

    try:
        for suffix in ("-wal", "-shm"):
            for path_base in (db_path, tmp_path):
                sidecar = f"{path_base}{suffix}"
                if os.path.exists(sidecar):
                    try:
                        os.remove(sidecar)
                    except OSError:
                        pass

        os.rename(tmp_path, db_path)
        os.chmod(db_path, 0o600)
    except Exception:
        _cleanup_tmp_files(tmp_path)
        raise

    return warnings
