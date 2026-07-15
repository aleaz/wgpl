import os
import tempfile

import pytest

from wgpl import db, dbpath
from wgpl.exceptions import WgplException


def test_open_database_rejects_symlink(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "real.db")
        with open(target, "wb") as f:
            f.write(b"")
        os.chmod(target, 0o600)

        link = os.path.join(td, "link.db")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported in this environment")

        with pytest.raises(WgplException, match="symlink"):
            dbpath.open_database(link, create=True)


def test_open_database_sets_secure_permissions(tmp_path) -> None:
    path = str(tmp_path / "secure.db")
    conn = dbpath.open_database(path, create=True, exclusive_create=True)
    conn.close()
    assert oct(os.stat(path).st_mode & 0o777) == oct(0o600)


def test_readonly_open_enforces_permissions(tmp_path) -> None:
    """fchmod is applied even on read-only opens."""
    db_path = str(tmp_path / "test.db")
    conn = dbpath.open_database(db_path, create=True)
    conn.close()
    os.chmod(db_path, 0o644)
    assert oct(os.stat(db_path).st_mode & 0o777) == oct(0o644)
    conn = dbpath.open_database(db_path, read_only=True)
    conn.close()
    assert oct(os.stat(db_path).st_mode & 0o777) == oct(0o600)


def test_init_db_uses_secure_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "wgpl.db")
        monkeypatch.setenv("WGPL_DB_PATH", path)
        db.init_db(path)
        assert oct(os.stat(path).st_mode & 0o777) == oct(0o600)
