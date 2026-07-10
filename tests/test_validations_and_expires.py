import pytest
from wgpl import core, db
from wgpl.core import validate_endpoint, validate_public_key


def test_validate_endpoint_valid():
    assert validate_endpoint("1.1.1.1") == "1.1.1.1"
    assert validate_endpoint("example.com") == "example.com"
    assert validate_endpoint("sub-domain.example.com") == "sub-domain.example.com"


def test_validate_endpoint_invalid():
    with pytest.raises(ValueError):
        validate_endpoint("!@#$")
    with pytest.raises(ValueError):
        validate_endpoint("")
    with pytest.raises(ValueError):
        validate_endpoint("http://example.com")
    with pytest.raises(ValueError, match="IPv4"):
        validate_endpoint("2001:db8::1")


def test_validate_public_key_valid():
    # 32 bytes encoded in base64 is 44 characters
    valid_key = "a" * 43 + "="
    assert validate_public_key(valid_key) == valid_key


def test_validate_public_key_invalid():
    with pytest.raises(ValueError):
        validate_public_key("invalid-key")
    with pytest.raises(ValueError):
        validate_public_key("a" * 42 + "==")  # Valid base64, but wrong length


def test_update_peer_expires(wg0_interface: str) -> None:
    peer = core.add_peer(wg0_interface, "test-expire-update")
    peer_id = peer["id"]

    # Update expires
    updated = core.update_peer(wg0_interface, peer_id, expires="30d")
    assert updated["expires_at"] is not None

    # Verify in DB
    with db.transaction() as conn:
        db_peer = db.get_peer(peer_id, conn=conn)
    assert db_peer is not None
    assert db_peer["expires_at"] is not None

    # Clear expires
    cleared = core.update_peer(wg0_interface, peer_id, clear_expires=True)
    assert cleared["expires_at"] is None
