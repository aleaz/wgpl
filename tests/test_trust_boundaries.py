import os
import tempfile

import pytest

from wgpl import core, db, wireguard
from wgpl.db import AuditEntityType, AuditEventType
from wgpl.exceptions import WgBinaryNotFoundError, WgplException


def test_db_path_rejects_symlink(monkeypatch: pytest.MonkeyPatch) -> None:
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

        monkeypatch.setenv("WGPL_DB_PATH", link)
        with pytest.raises(WgplException, match="symlink"):
            db.init_db(link)


def test_audit_exec_cmd_sanitized_in_metadata(
    wg0_interface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WGPL_EXEC_CMD", "wgpl\nBAD\rCMD\tARG")
    peer = core.add_peer(wg0_interface, "phone")
    events = core.list_peer_audit_history(str(peer["id"]), wg0_interface)
    assert len(events) == 1

    exec_cmd = events[0]["metadata"]["exec_cmd"]
    assert "\n" not in exec_cmd
    assert "\r" not in exec_cmd
    assert "\t" not in exec_cmd


def test_audit_metadata_rejects_non_json_serializable(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    with pytest.raises(WgplException, match="JSON-serializable"):
        with db.transaction() as conn:
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=str(peer["id"]),
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"bad": object()},
                conn=conn,
            )


def test_audit_metadata_rejects_too_large_string(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    with pytest.raises(WgplException, match="too large"):
        with db.transaction() as conn:
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=str(peer["id"]),
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"exec_cmd": "a" * 5000},
                conn=conn,
            )


def test_wg_bin_rejects_symlink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.getuid() == 0:
        pytest.skip("Root runs ignore WGPL_WG_BIN in wireguard._get_wg_bin")

    with tempfile.TemporaryDirectory() as td:
        real = os.path.join(td, "wg-real")
        with open(real, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(real, 0o700)

        link = os.path.join(td, "wg-link")
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported in this environment")

        monkeypatch.setenv("WGPL_WG_BIN", link)
        with pytest.raises(WgBinaryNotFoundError, match="symlink"):
            wireguard._get_wg_bin()
