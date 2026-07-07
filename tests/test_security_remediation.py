"""Tests for structural security remediation (PeerAccess, schema on open, lifecycle)."""

import pytest
from typer.testing import CliRunner

from wgpl import core, db, wireguard
from wgpl.cli import app
from wgpl.exceptions import (
    InterfaceDisambiguationRequiredError,
    PeerInterfaceMismatchError,
    WgplException,
)

runner = CliRunner()


@pytest.fixture
def dual_interface(wgpl_db: str) -> dict[str, str]:
    """Two interfaces with one peer each."""
    pk1 = wireguard.generate_keypair().public_key
    pk2 = wireguard.generate_keypair().public_key
    iface_a = str(db.add_interface("wg0", "a.example.com", pk1, "10.0.0.0/24", 51820))
    iface_b = str(db.add_interface("wg1", "b.example.com", pk2, "10.1.0.0/24", 51821))
    peer_a = core.add_peer(iface_a, "peer-a", ip_address="10.0.0.2")
    core.add_peer(iface_b, "peer-b", ip_address="10.1.0.2")
    return {
        "iface_a": iface_a,
        "iface_b": iface_b,
        "peer_a_id": str(peer_a["id"]),
        "peer_a_prefix": str(peer_a["id"]).replace("-", "")[:12],
    }


def test_show_secrets_requires_interface_with_multiple_interfaces(
    dual_interface: dict[str, str],
) -> None:
    with pytest.raises(InterfaceDisambiguationRequiredError):
        core.resolve_peer_ref(
            dual_interface["peer_a_prefix"],
            None,
            access=core.PeerAccess.READ_SENSITIVE,
        )


def test_show_secrets_rejects_cross_interface_prefix(
    dual_interface: dict[str, str],
) -> None:
    with pytest.raises(PeerInterfaceMismatchError):
        core.resolve_peer_ref(
            dual_interface["peer_a_id"],
            dual_interface["iface_b"],
            access=core.PeerAccess.READ_SENSITIVE,
        )


def test_export_secret_requires_interface_with_multiple_interfaces(
    dual_interface: dict[str, str],
) -> None:
    with pytest.raises(InterfaceDisambiguationRequiredError):
        core.get_peer_config(dual_interface["peer_a_prefix"])


def test_peer_history_scoped_to_interface(dual_interface: dict[str, str]) -> None:
    events = core.list_peer_audit_history(
        dual_interface["peer_a_id"], dual_interface["iface_a"]
    )
    assert any(e["event_type"] == "created" for e in events)


def test_live_db_rejects_extra_trigger(wg0_interface: str) -> None:
    with db.get_db() as conn:
        conn.execute(
            """
            CREATE TRIGGER trg_evil AFTER INSERT ON peers
            BEGIN SELECT 1; END;
            """
        )
        conn.commit()

    with pytest.raises(WgplException, match="schema contract"):
        with db.get_db():
            pass


def test_validate_state_invalid_address_pool_reports_issue(wg0_interface: str) -> None:
    with db.get_db() as conn:
        conn.execute(
            "UPDATE interfaces SET address_pool = ? WHERE id = ?",
            ("not-a-cidr", wg0_interface),
        )
        conn.commit()
        result = core.validate_state(wg0_interface, conn=conn)

    assert result["status"] == "error"
    issues = result["issues"]
    assert isinstance(issues, list)
    codes = {issue["code"] for issue in issues}
    assert "invalid_address_pool" in codes


def test_db_doctor_reports_empty_deleted_at(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    with db.transaction(verify=False) as conn:
        conn.execute(
            "UPDATE peers SET deleted_at = ? WHERE id = ?",
            ("", str(peer["id"])),
        )

    issues = core.diagnose_database()
    codes = {str(issue["code"]) for issue in issues}
    assert "empty_deleted_at" in codes


def test_db_doctor_repair_normalizes_empty_deleted_at(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "phone")
    peer_id = str(peer["id"])
    with db.transaction(verify=False) as conn:
        conn.execute("UPDATE peers SET deleted_at = ? WHERE id = ?", ("", peer_id))

    core.repair_database()

    row = db.get_peer(peer_id)
    assert row is not None
    assert row["deleted_at"] is None


def test_cli_peer_show_secrets_requires_interface_multi(
    dual_interface: dict[str, str],
) -> None:
    result = runner.invoke(
        app,
        ["peer", "show", dual_interface["peer_a_prefix"], "--show-secrets"],
    )
    assert result.exit_code == 1
    assert "interface" in result.stderr.lower()
