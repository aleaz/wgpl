import os
import stat

import pytest
from typer.testing import CliRunner

from wgpl import core
from wgpl.cli import app
from wgpl import dbpath
from wgpl.exceptions import WgplException

runner = CliRunner()


def test_open_exclusive_output_rejects_symlink(tmp_path) -> None:
    target = tmp_path / "real.png"
    target.write_bytes(b"data")
    link = tmp_path / "out.png"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    with pytest.raises(WgplException, match="symlink"):
        dbpath.open_exclusive_output(str(link))


def test_open_exclusive_output_creates_secure_file(tmp_path) -> None:
    path = tmp_path / "out.db"
    fd = dbpath.open_exclusive_output(str(path))
    os.close(fd)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_dump_database_rejects_symlink_output(wg0_interface: str, tmp_path) -> None:
    target = tmp_path / "real.db"
    link = tmp_path / "link.db"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    with pytest.raises(WgplException, match="symlink"):
        core.dump_database(str(link))


def test_cli_db_dump_rejects_symlink_output(wg0_interface: str, tmp_path) -> None:
    target = tmp_path / "real.db"
    link = tmp_path / "link.db"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    result = runner.invoke(app, ["db", "dump", "-o", str(link)])
    assert result.exit_code == 1
    assert "symlink" in result.stderr.lower() or "WGPL Error" in result.stderr


def test_cli_peer_qr_rejects_symlink_output(wg0_interface: str, tmp_path) -> None:
    from wgpl import core as core_mod

    peer = core_mod.add_peer(wg0_interface, "qrpeer")
    target = tmp_path / "real.png"
    link = tmp_path / "qr.png"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    result = runner.invoke(
        app, ["peer", "qr", str(peer["id"]), "-o", str(link)]
    )
    assert result.exit_code == 1
    assert "symlink" in result.stderr.lower() or "WGPL Error" in result.stderr
