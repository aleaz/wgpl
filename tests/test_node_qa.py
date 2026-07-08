"""Adversarial regression tests for the node group and node/peer interplay.

Codifies findings from the live QA sweep of the post-Node CLI. Fixes for real
bugs land at the integrity/core layer; these tests lock in the intended
behaviour so regressions are caught by the automated gate.
"""

from __future__ import annotations

import pytest

from wgpl import core, db
from wgpl.exceptions import (
    NodeAlreadyExistsError,
    NodeHasPeersError,
    NodeNotFoundError,
    PeerAlreadyExistsError,
    WgplException,
)


# --- node add: identity validation ---------------------------------------


def test_node_add_duplicate_global_name_rejected(wg0_interface: str) -> None:
    core.add_node("laptop")
    with pytest.raises(NodeAlreadyExistsError):
        core.add_node("laptop")


@pytest.mark.parametrize(
    "bad_name",
    [
        "",
        "   ",
        "a" * 65,
        "ev;il`whoami`",
        "café",
        "-startshyphen",
    ],
)
def test_node_add_invalid_name_rejected(wg0_interface: str, bad_name: str) -> None:
    with pytest.raises(ValueError):
        core.add_node(bad_name)
    assert core.list_nodes() == []


@pytest.mark.parametrize(
    "bad_desc",
    ["line\nbreak", "bell\x07here", "carriage\rreturn"],
)
def test_node_add_desc_control_chars_rejected(
    wg0_interface: str, bad_desc: str
) -> None:
    with pytest.raises(WgplException):
        core.add_node("box", desc=bad_desc)
    assert core.list_nodes() == []


# --- node remove / prune lifecycle ----------------------------------------


def test_node_remove_guarded_when_attached(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    with pytest.raises(NodeHasPeersError):
        core.remove_node("phone")
    # node and its attachment survive a rejected remove
    assert {n["name"] for n in core.list_nodes()} == {"phone"}
    assert len(core.list_peers(wg0_interface)) == 1


def test_node_remove_force_cascades_attachments(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    core.remove_node("phone", force=True)
    assert core.list_nodes() == []
    assert core.list_peers(wg0_interface) == []


def test_node_prune_removes_only_orphans(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "attached")
    core.add_node("orphan")
    removed = core.prune_nodes()
    assert removed == 1
    assert {n["name"] for n in core.list_nodes()} == {"attached"}


# --- peer add: hybrid find-or-create vs strict --node ----------------------


def test_peer_add_find_or_create_creates_node(wg0_interface: str) -> None:
    result = core.add_peer(wg0_interface, "phone")
    assert result["node_created"] is True
    assert result["name"] == "phone"


def test_peer_add_strict_node_attaches_existing(wg0_interface: str) -> None:
    core.add_node("laptop")
    result = core.add_peer(wg0_interface, node_ref="laptop")
    assert result["node_created"] is False
    assert result["name"] == "laptop"


def test_peer_add_strict_node_nonexistent_fails(wg0_interface: str) -> None:
    with pytest.raises(NodeNotFoundError):
        core.add_peer(wg0_interface, node_ref="ghost")


def test_peer_add_same_node_twice_rejected(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    with pytest.raises(PeerAlreadyExistsError):
        core.add_peer(wg0_interface, "phone")
    with pytest.raises(PeerAlreadyExistsError):
        core.add_peer(wg0_interface, node_ref="phone")


def test_peer_add_requires_exactly_one_of_name_or_node(wg0_interface: str) -> None:
    with pytest.raises(ValueError):
        core.add_peer(wg0_interface)
    core.add_node("laptop")
    with pytest.raises(ValueError):
        core.add_peer(wg0_interface, "laptop", node_ref="laptop")


def test_failed_peer_add_does_not_leak_orphan_node(wg0_interface: str) -> None:
    """find-or-create inserts the node before routing validation; a later
    failure must roll back the node too (single transaction)."""
    with pytest.raises((WgplException, ValueError)):
        core.add_peer(
            wg0_interface,
            "router",
            role=core.PeerRole.SUBNET_ROUTER,  # missing routed_networks
        )
    assert core.list_nodes() == []


def test_failed_peer_add_ip_collision_rolls_back_new_node(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "existing", ip_address="10.0.0.5")
    with pytest.raises(WgplException):
        core.add_peer(wg0_interface, "fresh", ip_address="10.0.0.5")
    assert {n["name"] for n in core.list_nodes()} == {"existing"}


# --- node identity persists across the peer lifecycle ----------------------


def test_node_rename_reflected_in_peer_view(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    core.update_node("phone", name="phone2")
    names = {p["name"] for p in core.list_peers(wg0_interface)}
    assert names == {"phone2"}


def test_soft_delete_keeps_node_and_readd_reclaims_slot(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    core.remove_peer(wg0_interface, str(peer["id"]))

    # identity survives the peer soft-delete
    node = core.get_node_by_ref("phone")
    assert node["attachment_count"] == 0

    core.add_peer(wg0_interface, "phone")
    node = core.get_node_by_ref("phone")
    assert node["attachment_count"] == 1
    # exactly one node named phone (no duplicate identity)
    assert [n["name"] for n in core.list_nodes()].count("phone") == 1


# --- ref resolution ---------------------------------------------------------


def test_node_ref_exact_name_wins(wg0_interface: str) -> None:
    node = core.add_node("deadbeef")
    resolved = core.get_node_by_ref("deadbeef")
    assert resolved["id"] == node["id"]


def test_node_ref_sql_injection_neutralized(wg0_interface: str) -> None:
    core.add_peer(wg0_interface, "phone")
    with pytest.raises(NodeNotFoundError):
        core.get_node_by_ref("x'; DROP TABLE nodes;--")
    # table intact and data preserved
    with db.get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    assert count == 1
