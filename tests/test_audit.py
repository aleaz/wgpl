"""Audit log and interface remove guard tests."""

import datetime

import pytest

from wgpl import core, db
from wgpl.db import AuditEntityType, AuditEventType
from wgpl.exceptions import (
    InterfaceHasPeersError,
    IpAlreadyInUseError,
    PeerAlreadyExistsError,
    WgplException,
)


def _count_audit(
    *,
    entity_type: AuditEntityType | None = None,
    entity_id: str | None = None,
) -> int:
    return len(
        db.list_audit_events(entity_type=entity_type, entity_id=entity_id, limit=1000)
    )


def test_add_peer_logs_created_event(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.2")
    assert peer["id"] is not None
    events = core.list_peer_audit_history(str(peer["id"]), wg0_interface)
    assert len(events) == 1
    assert events[0]["event_type"] == AuditEventType.CREATED
    assert events[0]["metadata"] is None or "private_key" not in str(
        events[0]["metadata"]
    )


def test_remove_peer_soft_and_hard_audit(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])
    core.remove_peer(wg0_interface, peer_id)
    events = core.list_peer_audit_history(peer_id, wg0_interface)
    removed_events = [e for e in events if e["event_type"] == AuditEventType.REMOVED]
    assert len(removed_events) == 1
    assert not any(e.get("metadata") == {"hard": True} for e in removed_events)

    core.remove_peer(wg0_interface, peer_id)
    events = core.list_peer_audit_history(peer_id, wg0_interface)
    removed_events = [e for e in events if e["event_type"] == AuditEventType.REMOVED]
    assert len(removed_events) == 1

    core.remove_peer(wg0_interface, peer_id, hard=True)
    events = core.list_peer_audit_history(peer_id, wg0_interface)
    hard_events = [e for e in events if e["event_type"] == AuditEventType.REMOVED]
    assert len(hard_events) == 2
    assert any(e.get("metadata") == {"hard": True} for e in hard_events)


def test_reclaim_expired_logs_reclaimed_and_old_row_soft_deleted(
    wg0_interface: str,
) -> None:
    peer = core.add_peer(wg0_interface, "phone", ip_address="10.0.0.3", expires="1h")
    old_id = str(peer["id"])

    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, old_id))
        conn.commit()

    old_peer = db.get_peer(old_id)
    assert old_peer is not None
    assert core.get_peer_status(old_peer) == "Expired"

    new_peer = core.add_peer(wg0_interface, "phone2", ip_address="10.0.0.3")
    old_peer_row = db.get_peer(old_id)
    assert old_peer_row is not None
    assert old_peer_row["deleted_at"] is not None

    old_events = core.list_peer_audit_history(old_id, wg0_interface)
    assert any(e["event_type"] == AuditEventType.CREATED for e in old_events)
    reclaimed = [e for e in old_events if e["event_type"] == AuditEventType.RECLAIMED]
    assert len(reclaimed) == 1
    assert reclaimed[0]["metadata"]["replaced_by_peer_id"] == new_peer["id"]
    assert reclaimed[0]["metadata"]["slot"] == ["ip"]

    new_events = core.list_peer_audit_history(str(new_peer["id"]), wg0_interface)
    assert any(e["event_type"] == AuditEventType.CREATED for e in new_events)


def test_add_peer_active_collision_ip(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "first", ip_address="10.0.0.4")
    with pytest.raises(IpAlreadyInUseError):
        core.add_peer(wg0_interface, "second", ip_address="10.0.0.4")


def test_add_peer_active_collision_name(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "taken", ip_address="10.0.0.5")
    with pytest.raises(PeerAlreadyExistsError):
        core.add_peer(wg0_interface, "taken", ip_address="10.0.0.6")


def test_prune_logs_one_event_per_peer(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    core.remove_peer(wg0_interface, str(peer["id"]))
    before = _count_audit(entity_type=AuditEntityType.PEER, entity_id=str(peer["id"]))
    assert core.prune_peers(wg0_interface) == 1
    events = core.list_peer_audit_history(str(peer["id"]), wg0_interface)
    pruned = [e for e in events if e["event_type"] == AuditEventType.PRUNED]
    assert len(pruned) == 1
    assert pruned[0]["metadata"]["was_soft_deleted"] is True
    assert before >= 2


def test_interface_remove_blocked_with_peers(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    with pytest.raises(InterfaceHasPeersError):
        core.remove_interface(wg0_interface)
    assert db.get_interface(int(wg0_interface)) is not None


def test_interface_remove_blocked_with_expired_peer_only(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone", expires="1h")
    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, peer["id"]))
        conn.commit()
    with pytest.raises(InterfaceHasPeersError):
        core.remove_interface(wg0_interface)


def test_interface_remove_force_audit_cascade(wg0_interface: str) -> None:
    p1 = core.add_peer(wg0_interface, "a", ip_address="10.0.0.2")
    p2 = core.add_peer(wg0_interface, "b", ip_address="10.0.0.3")
    core.remove_interface(wg0_interface, force=True)
    assert db.get_interface(int(wg0_interface)) is None
    assert db.get_peer(p1["id"]) is None
    assert db.get_peer(p2["id"]) is None

    iface_events = core.list_interface_audit_history(wg0_interface)
    assert any(e["event_type"] == AuditEventType.REMOVED for e in iface_events)

    for pid in (str(p1["id"]), str(p2["id"])):
        events = core.list_peer_audit_history(pid)
        assert any(e["event_type"] == AuditEventType.CASCADE_REMOVED for e in events)


def test_interface_remove_empty_no_force(wg0_interface: str) -> None:
    core.remove_interface(wg0_interface)
    assert db.get_interface(int(wg0_interface)) is None
    events = core.list_interface_audit_history(wg0_interface)
    assert len(events) == 1
    assert events[0]["event_type"] == AuditEventType.REMOVED
    assert events[0]["metadata"]["peer_count"] == 0


def test_interface_add_logs_created(wgpl_db: str) -> None:
    from wgpl import wireguard

    pubkey = wireguard.generate_keypair().public_key
    core.add_interface("wg1", "vpn.example.com", pubkey, "10.0.1.0/24", port=51821)
    events = core.list_interface_audit_history("wg1")
    assert len(events) == 1
    assert events[0]["event_type"] == AuditEventType.CREATED


def test_peer_update_logs_updated_event(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    core.update_peer(wg0_interface, peer_id, name="renamed")

    events = core.list_peer_audit_history(peer_id, wg0_interface)
    updated = [e for e in events if e["event_type"] == AuditEventType.UPDATED]
    assert len(updated) == 1
    assert updated[0]["metadata"]["fields"]["name"]["new"] == "renamed"
    assert updated[0]["metadata"]["fields"]["name"]["old"] == "phone"


def test_interface_update_logs_updated_event(wg0_interface: str) -> None:
    core.update_interface(wg0_interface, endpoint="vpn2.example.com")

    events = core.list_interface_audit_history(wg0_interface)
    updated = [e for e in events if e["event_type"] == AuditEventType.UPDATED]
    assert len(updated) == 1
    assert updated[0]["metadata"]["fields"]["endpoint"]["new"] == "vpn2.example.com"


def test_audit_metadata_rejects_private_key(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    with pytest.raises(WgplException, match="secret field"):
        with db.transaction() as conn:
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=str(peer["id"]),
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"private_key": "leak"},
                conn=conn,
            )


def test_list_peer_audit_history_limit(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    with db.transaction() as conn:
        for _ in range(10):
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=peer_id,
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"fields": ["name"]},
                conn=conn,
            )

    all_events = core.list_peer_audit_history(peer_id, wg0_interface, limit=100)
    limited = core.list_peer_audit_history(peer_id, wg0_interface, limit=5)
    assert len(all_events) == 11  # created + 10 updated
    assert len(limited) == 5


def test_add_peer_rolls_back_when_audit_fails_on_second_event(
    wg0_interface: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    expired = core.add_peer(wg0_interface, "old", ip_address="10.0.0.3", expires="1h")
    old_id = str(expired["id"])
    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, old_id))
        conn.commit()

    audit_calls = 0
    from wgpl import audit as audit_mod
    from wgpl import ipam as ipam_mod

    original = audit_mod._audit_peer_from_row

    def failing_audit(*args, **kwargs):
        nonlocal audit_calls
        audit_calls += 1
        if audit_calls >= 2:
            raise WgplException("audit failed")
        return original(*args, **kwargs)

    monkeypatch.setattr(audit_mod, "_audit_peer_from_row", failing_audit)
    monkeypatch.setattr(ipam_mod, "_audit_peer_from_row", failing_audit)
    monkeypatch.setattr(core, "_audit_peer_from_row", failing_audit)

    with pytest.raises(WgplException, match="audit failed"):
        core.add_peer(wg0_interface, "new", ip_address="10.0.0.3")

    assert db.get_peer(old_id) is not None
    assert audit_calls == 2
    peers = db.list_peers(int(wg0_interface))
    assert (
        len(
            [
                p
                for p in peers
                if p["ip_address"] == "10.0.0.3" and core.get_peer_status(p) == "Active"
            ]
        )
        == 0
    )


def test_reclaim_via_peer_update_logs_reclaimed(wg0_interface: str) -> None:
    expired = core.add_peer(wg0_interface, "old", ip_address="10.0.0.3", expires="1h")
    old_id = str(expired["id"])
    past = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
    ).isoformat()
    with db.get_db() as conn:
        conn.execute("UPDATE peers SET expires_at = ? WHERE id = ?", (past, old_id))
        conn.commit()

    active = core.add_peer(wg0_interface, "active", ip_address="10.0.0.4")
    active_id = str(active["id"])

    core.update_peer(wg0_interface, active_id, ip_address="10.0.0.3")

    old_peer_row = db.get_peer(old_id)
    assert old_peer_row is not None
    assert old_peer_row["deleted_at"] is not None
    updated = db.get_peer(active_id)
    assert updated is not None
    assert updated["ip_address"] == "10.0.0.3"

    old_events = core.list_peer_audit_history(old_id, wg0_interface)
    reclaimed = [e for e in old_events if e["event_type"] == AuditEventType.RECLAIMED]
    assert len(reclaimed) == 1
    assert reclaimed[0]["metadata"]["replaced_by_peer_id"] == active_id


def test_audit_metadata_rejects_preshared_key(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    with pytest.raises(WgplException, match="secret field"):
        with db.transaction() as conn:
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=str(peer["id"]),
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"preshared_key": "leak"},
                conn=conn,
            )


def test_list_peer_audit_history_limit_returns_most_recent(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    with db.transaction() as conn:
        for _ in range(10):
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=peer_id,
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"fields": ["name"]},
                conn=conn,
            )

    limited = core.list_peer_audit_history(peer_id, wg0_interface, limit=5)
    assert len(limited) == 5
    assert all(e["event_type"] == AuditEventType.UPDATED for e in limited)
    assert limited[0]["event_type"] == AuditEventType.UPDATED


def test_list_peer_audit_history_offset_skips_newest(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    with db.transaction() as conn:
        for _ in range(10):
            db.append_audit_event(
                entity_type=AuditEntityType.PEER,
                entity_id=peer_id,
                event_type=AuditEventType.UPDATED,
                interface=wg0_interface,
                metadata={"fields": ["name"]},
                conn=conn,
            )

    page0 = core.list_peer_audit_history(peer_id, wg0_interface, limit=5, offset=0)
    page1 = core.list_peer_audit_history(peer_id, wg0_interface, limit=5, offset=5)
    tail = core.list_peer_audit_history(peer_id, wg0_interface, limit=5, offset=10)

    assert len(page0) == 5
    assert len(page1) == 5
    assert len(tail) == 1
    assert tail[0]["event_type"] == AuditEventType.CREATED
    assert {e["id"] for e in page0}.isdisjoint({e["id"] for e in page1})


def test_peer_update_no_audit_when_value_unchanged(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])

    core.update_peer(wg0_interface, peer_id, name="phone")

    events = core.list_peer_audit_history(peer_id, wg0_interface)
    updated = [e for e in events if e["event_type"] == AuditEventType.UPDATED]
    assert updated == []


def test_interface_update_no_audit_when_endpoint_unchanged(wg0_interface: str) -> None:
    core.update_interface(wg0_interface, endpoint="vpn.example.com")

    events = core.list_interface_audit_history(wg0_interface)
    updated = [e for e in events if e["event_type"] == AuditEventType.UPDATED]
    assert updated == []
